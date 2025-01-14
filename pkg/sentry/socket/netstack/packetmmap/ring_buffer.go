// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packetmmap

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type ringBuffer struct {
	framesPerBlock uint32
	frameSize      uint32
	frameMax       uint32
	blockSize      uint32
	numBlocks      uint32

	ep *Endpoint
	// +checklocks:ep.mu
	head uint32
	// +checklocks:ep.mu
	rxOwnerMap map[uint32]struct{}

	dataMu sync.RWMutex
	// +checklocks:dataMu
	size uint64
	// +checklocks:dataMu
	mappedData fsutil.FileRangeSet

	mf *pgalloc.MemoryFile
}

// init initializes a PacketRingBuffer.
//
// +checklocks:rb.ep.mu
// +checklocksalias:rb.ep.mu=ep.mu
func (rb *ringBuffer) init(req *tcpip.TpacketReq, ep *Endpoint) {
	rb.blockSize = req.TpBlockSize
	rb.framesPerBlock = req.TpBlockSize / req.TpFrameSize
	rb.frameMax = req.TpFrameNr - 1
	rb.frameSize = req.TpFrameSize
	rb.numBlocks = req.TpBlockNr

	rb.ep = ep

	rb.rxOwnerMap = make(map[uint32]struct{}, req.TpFrameNr)
	rb.head = 0

	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	rb.size = uint64(req.TpBlockSize) * uint64(req.TpBlockNr)
}

// destroy destroys the packet ring buffer.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) destroy() {
	rb.dataMu.Lock()
	rb.mappedData.DropAll(rb.mf)
	rb.dataMu.Unlock()
	*rb = ringBuffer{}
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (rb *ringBuffer) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	if opts.Length != rb.size {
		return linuxerr.EINVAL
	}
	mf := pgalloc.MemoryFileFromContext(ctx)
	if mf == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFile))
	}
	rb.mf = mf
	// The mapped data is empty at this point, so we know any gap will be large
	// enough to hold the requested number of blocks.
	gap := rb.mappedData.FindGap(opts.Offset)
	if !gap.Ok() {
		return linuxerr.EINVAL
	}
	for i := uint32(opts.Offset); i < rb.numBlocks; i++ {
		start := uint64(i * rb.blockSize)
		end := start + uint64(rb.blockSize)
		fr, err := rb.mf.Allocate(uint64(rb.blockSize), pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: pgalloc.MemoryCgroupIDFromContext(ctx)})
		if err != nil {
			return err
		}
		gap = rb.mappedData.Insert(gap, memmap.MappableRange{Start: start, End: end}, fr.Start).NextGap()
	}
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (rb *ringBuffer) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	var beyondEOF bool
	if required.End > rb.size {
		if required.Start >= rb.size {
			return nil, &memmap.BusError{Err: io.EOF}
		}
		beyondEOF = true
		required.End = rb.size
	}
	if optional.End > rb.size {
		optional.End = rb.size
	}
	var ts []memmap.Translation
	for seg := rb.mappedData.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   rb.mf,
			Offset: seg.FileRangeOf(segMR).Start,
			Perms:  hostarch.AnyAccess,
		})
	}
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// writeStatus writes the status of a frame to the ring buffer's internal
// mappings at the provided frame number. It also clears the owner map for the
// frame number if setting it to TP_STATUS_USER.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) writeStatus(frameNum uint32, status uint64) error {
	if status&linux.TP_STATUS_USER != 0 {
		defer func() {
			delete(rb.rxOwnerMap, frameNum)
		}()
	}
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	// Status is the first uint64 in the frame.
	hostarch.ByteOrder.PutUint64(ims.Head().ToSlice()[:8], status)
	return nil
}

// writeFrame writes a frame to the ring buffer's internal mappings at the
// provided frame number.
func (rb *ringBuffer) writeFrame(frameNum uint32, hdr linux.TpacketHdr, pktOffset uint32, pkt buffer.Buffer) error {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	// The status is set separately to ensure the frame is written before the
	// status is set.
	hdr.TpStatus = linux.TP_STATUS_KERNEL
	hdrBytes := marshal.Marshal(&hdr)
	frame := buffer.MakeWithData(hdrBytes)
	frame.GrowTo(int64(pktOffset), true)
	frame.Merge(&pkt)
	br := frame.AsBufferReader()
	defer br.Close()

	rdr := safemem.FromIOReader{Reader: &br}
	if _, err = rdr.ReadToBlocks(ims); err != nil {
		return err
	}
	return nil
}

// incHead increments the head of the ring buffer.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) incHead() {
	if rb.head == rb.frameMax {
		rb.head = 0
	} else {
		rb.head++
	}
}

// currFrameStatus returns the status of the current frame.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) currFrameStatus() (uint64, error) {
	return rb.frameStatus(rb.head)
}

// prevFrameStatus returns the status of the frame before the current
// frame.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) prevFrameStatus() (uint64, error) {
	prev := rb.head - 1
	if rb.head == 0 {
		prev = rb.frameMax
	}
	return rb.frameStatus(prev)
}

// testAndMarkHead tests whether the head slot is available and marks it
// as owned if it is.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) testAndMarkHead() (uint32, bool) {
	if _, ok := rb.rxOwnerMap[rb.head]; ok {
		return 0, false
	}
	rb.rxOwnerMap[rb.head] = struct{}{}
	return rb.head, true

}

// hasRoom returns true if the ring buffer has room for a new frame at head.
//
// +checklocks:rb.ep.mu
func (rb *ringBuffer) hasRoom() bool {
	status, err := rb.currFrameStatus()
	if err != nil {
		return false
	}
	return status == linux.TP_STATUS_KERNEL
}

// bufferSize returns the size of the ring buffer in bytes.
func (rb *ringBuffer) bufferSize() uint64 {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()
	return rb.size
}

func (rb *ringBuffer) internalMappingsForFrame(frameNum uint32, at hostarch.AccessType) (safemem.BlockSeq, error) {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()

	blockIdx := uint32(frameNum / rb.framesPerBlock)
	frameIdx := uint32(frameNum % rb.framesPerBlock)

	seg := rb.mappedData.LowerBoundSegment(uint64(blockIdx * rb.blockSize))
	if !seg.Ok() {
		return safemem.BlockSeq{}, linuxerr.EFAULT
	}
	frameStart := seg.FileRange().Start + (uint64(blockIdx) * uint64(rb.blockSize)) + (uint64(frameIdx) * uint64(rb.frameSize))
	frameEnd := frameStart + uint64(rb.frameSize)

	frameFR := memmap.FileRange{Start: frameStart, End: frameEnd}
	return rb.mf.MapInternal(frameFR, at)
}

func (rb *ringBuffer) frameStatus(frameNum uint32) (uint64, error) {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Read)
	if err != nil {
		return 0, err
	}
	// Status is the first uint64 in the frame.
	return hostarch.ByteOrder.Uint64(ims.Head().ToSlice()[:8]), err
}
