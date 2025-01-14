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

// Package packetmmap contains the packet mmap implementation for netstack.
//
// See https://docs.kernel.org/networking/packet_mmap.html for a full
// description of the PACKET_MMAP interface.
package packetmmap

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ stack.PacketMMapEndpoint = (*Endpoint)(nil)
var _ memmap.Mappable = (*Endpoint)(nil)

// ringBufferMode is the mode of a packet ring buffer.
type ringBufferMode uint

const (
	noRingBuffer ringBufferMode = 1 << iota
	rxRingBuffer
	txRingBuffer
)

// Endpoint is a memmap.Mappable implementation for stack.PacketMMapEndpoint. It
// implements the PACKET_MMAP interface as described in
// https://docs.kernel.org/networking/packet_mmap.html.
type Endpoint struct {
	mu           sync.Mutex
	rxRingBuffer ringBuffer
	txRingBuffer ringBuffer

	cooked      bool
	copyHandler stack.PacketMMapCopyHandler
	mode        ringBufferMode

	stack *stack.Stack
	stats *tcpip.TransportEndpointStats
	wq    *waiter.Queue

	mappingsMu sync.Mutex
	// +checklocks:mappingsMu
	mappings memmap.MappingSet
}

// InitPacketMMap implements stack.PacketMMapEndpoint.InitPacketMMap.
func (m *Endpoint) InitPacketMMap(opts stack.InitPacketMMapOpts) tcpip.Error {
	m.stack = opts.Stack
	m.wq = opts.Wq
	m.cooked = opts.Cooked
	m.copyHandler = opts.CopyHandler
	m.stats = opts.Stats
	m.mu.Lock()
	defer m.mu.Unlock()
	if opts.RxReq != nil {
		m.rxRingBuffer.init(opts.RxReq, m)
		m.mode |= rxRingBuffer
	}
	if opts.TxReq != nil {
		m.txRingBuffer.init(opts.TxReq, m)
		m.mode |= txRingBuffer
	}
	return nil
}

// Close implements stack.PacketMMapEndpoint.Close.
func (m *Endpoint) Close() {
	if m.mode&rxRingBuffer != 0 {
		m.rxRingBuffer.destroy()
	}
	if m.mode&txRingBuffer != 0 {
		m.txRingBuffer.destroy()
	}
}

// Readiness implements stack.PacketMmapEndpoint.Readiness.
func (m *Endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.WritableEvents & mask
	st, err := m.rxRingBuffer.prevFrameStatus()
	if err != nil {
		return result
	}
	if st != linux.TP_STATUS_KERNEL {
		result |= waiter.ReadableEvents
	}
	return result
}

// HandlePacket implements stack.PacketMMapEndpoint.HandlePacket.
func (m *Endpoint) HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	const minMacLen = 16
	var (
		status                           = uint64(linux.TP_STATUS_USER)
		pktOffset, netOffset, dataLength uint32
		clone                            *stack.PacketBuffer
	)

	m.mu.Lock()
	if !m.rxRingBuffer.hasRoom() {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		return
	}
	m.mu.Unlock()

	if pkt.GSOOptions.Type != stack.GSONone && pkt.GSOOptions.NeedsCsum {
		status |= uint64(linux.TP_STATUS_CSUM_NOT_READY)
	}
	if pkt.GSOOptions.Type == stack.GSOTCPv4 || pkt.GSOOptions.Type == stack.GSOTCPv6 {
		status |= uint64(linux.TP_STATUS_GSO_TCP)
	}

	pktBuf := pkt.ToBuffer()
	if m.cooked {
		pktBuf.TrimFront(int64(len(pkt.LinkHeader().Slice()) + len(pkt.VirtioNetHeader().Slice())))
		// Cooked packet endpoints don't include the link-headers in received
		// packets.
		netOffset = linux.TPacketAlign(linux.TPACKET_HDRLEN) + minMacLen
		pktOffset = netOffset
	} else {
		virtioNetHdrLen := uint32(len(pkt.VirtioNetHeader().Slice()))
		macLen := uint32(len(pkt.LinkHeader().Slice())) + virtioNetHdrLen
		netOffset = linux.TPacketAlign(linux.TPACKET_HDRLEN + macLen)
		if macLen < minMacLen {
			netOffset = linux.TPacketAlign(linux.TPACKET_HDRLEN + minMacLen)
		}
		if virtioNetHdrLen > 0 {
			netOffset += virtioNetHdrLen
		}
		pktOffset = netOffset - macLen
	}
	if netOffset > uint32(^uint16(0)) {
		m.stack.Stats().DroppedPackets.Increment()
		return
	}
	dataLength = uint32(pktBuf.Size())

	// If the packet is too large to fit in the ring buffer, copy it to the
	// receive queue.
	if pktOffset+dataLength > m.rxRingBuffer.frameSize {
		clone = pkt.Clone()
		defer clone.DecRef()
		dataLength = m.rxRingBuffer.frameSize - pktOffset
		if int(dataLength) < 0 {
			dataLength = 0
		}
	}

	m.mu.Lock()
	tpStatus, err := m.rxRingBuffer.currFrameStatus()
	if err != nil || tpStatus != linux.TP_STATUS_KERNEL {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		return
	}

	slot, ok := m.rxRingBuffer.testAndMarkHead()
	if !ok {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		return
	}
	m.rxRingBuffer.incHead()

	if clone != nil {
		status |= uint64(linux.TP_STATUS_COPY)
		m.copyHandler(nicID, netProto, clone)
	}
	m.mu.Unlock()

	// Unlock around writing to the internal mappings to allow other threads to
	// write to the ring buffer.
	t := m.stack.Clock().Now()
	hdr := linux.TpacketHdr{
		TpLen:     uint32(pktBuf.Size()),
		TpSnaplen: dataLength,
		TpMac:     uint16(pktOffset),
		TpNet:     uint16(netOffset),
		TpSec:     uint32(t.Unix()),
		TpUsec:    uint32(t.UnixMicro() % 1e6),
	}
	pktBuf.Truncate(int64(dataLength))
	if err := m.rxRingBuffer.writeFrame(slot, hdr, pktOffset, pktBuf); err != nil {
		m.stack.Stats().DroppedPackets.Increment()
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rxRingBuffer.writeStatus(slot, status); err != nil {
		m.stack.Stats().DroppedPackets.Increment()
		return
	}
	m.stats.PacketsReceived.Increment()
	m.wq.Notify(waiter.ReadableEvents)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (m *Endpoint) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.AddMapping(ms, ar, offset, writable)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (m *Endpoint) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.RemoveMapping(ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (m *Endpoint) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.AddMapping(ms, dstAR, offset, writable)
	return nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (*Endpoint) InvalidateUnsavable(context.Context) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (m *Endpoint) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	var (
		ts  []memmap.Translation
		err error
	)
	if m.mode&rxRingBuffer != 0 {
		ts, err = m.rxRingBuffer.Translate(ctx, required, optional, at)
	}
	if m.mode&txRingBuffer != 0 {
		// Translate went outside the bounds of the RX ring buffer, which is valid
		// if there is also a TX ring buffer.
		if err != nil {
			if len(ts) > 0 {
				required.Start = ts[len(ts)-1].Source.End
				optional.Start = ts[len(ts)-1].Source.End
			}
		}
		var txTranslations []memmap.Translation
		txTranslations, err = m.txRingBuffer.Translate(ctx, required, optional, at)
		ts = append(ts, txTranslations...)
	}
	return ts, err
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (m *Endpoint) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if m.mode&rxRingBuffer != 0 {
		if err := m.rxRingBuffer.ConfigureMMap(ctx, opts); err != nil {
			return err
		}
	}
	if m.mode&txRingBuffer != 0 {
		txOpts := *opts
		txOpts.Offset += m.rxRingBuffer.bufferSize()
		if err := m.txRingBuffer.ConfigureMMap(ctx, &txOpts); err != nil {
			return err
		}
	}
	return nil
}
