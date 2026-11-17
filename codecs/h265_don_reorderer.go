// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"errors"
	"slices"
)

var (
	// errH265DONLRequired is returned when a packet fed to a H265DONReorderer
	// does not carry the DONL field the reorderer depends on.
	errH265DONLRequired = errors.New("h265: packet is missing its required DONL field")
	// errH265SimultaneousFUStartAndEnd is returned when a FU packet has both
	// the S and E bits set, which RFC 7798 does not allow.
	errH265SimultaneousFUStartAndEnd = errors.New("h265: FU packet has both S and E bits set")
)

// h265DONReordererMaxWindow bounds the reorder window. DON extension relies on
// the distance between any two consecutively received DONs staying below half
// of the 16-bit DONL space, so the window must remain strictly below 0x8000.
const h265DONReordererMaxWindow = 0x7FFF

// H265DONReordererStats counts how the H265DONReorderer disposed of input.
// Every packet fed to the reorderer is either emitted, still buffered, or
// accounted for in exactly one of the Dropped counters.
type H265DONReordererStats struct {
	// Emitted counts NALUs returned from Push or Flush.
	Emitted uint64
	// DroppedLate counts complete NALUs whose DON was already emitted.
	DroppedLate uint64
	// DroppedDuplicates counts complete NALUs whose DON was already buffered.
	DroppedDuplicates uint64
	// DroppedOverflow counts DON positions skipped because a newly arrived
	// DON was further than the reorder window ahead of them.
	DroppedOverflow uint64
	// DroppedIncomplete counts incomplete FU assemblies discarded because a
	// new start unit superseded them, a fragment arrived without a start
	// unit, or Flush was called while they were pending.
	DroppedIncomplete uint64
}

// h265FUKey isolates FU reassembly state by RTP timestamp and layer.
type h265FUKey struct {
	timestamp uint32
	layerID   uint8
}

// h265FUAssembly is the reassembly state of one fragmented NALU.
type h265FUAssembly struct {
	don           int64
	payloadHeader H265NALUHeader
	fuType        uint8
	parts         [][]byte
}

// H265DONReorderer consumes H265 RTP payloads that carry DONL/DOND fields
// (sprop-max-don-diff > 0, RFC 7798) and returns complete NALUs in decoding
// order. It expands Aggregation Packets, reassembles Fragmentation Units and
// buffers the resulting NALUs in a bounded reorder window keyed by their
// 32-bit extended DON.
//
// Packets arrive in network (RTP) order; Push returns the NALUs that become
// decodable as a result, each Annex-B framed (start code + NALU), matching
// the output format of H265Depacketizer. When the stream does not use DONL,
// keep using H265Depacketizer; its behavior is unchanged.
//
// Disposition rules are deterministic:
//   - malformed packets (short, bad type, missing DONL, S+E FU) make Push
//     return an error and leave the reorderer state untouched;
//   - a complete NALU whose DON was already emitted is dropped as late;
//   - a complete NALU whose DON is already buffered is dropped as duplicate;
//   - when a new DON is more than window positions ahead of the next DON to
//     emit, the missing positions in between are declared lost and skipped;
//   - an incomplete FU assembly is dropped when a new start unit with the
//     same (timestamp, layer) key arrives, when a non-start fragment arrives
//     without one, and on Flush;
//   - PACI packets are rejected with errUnhandledNALUType.
//
// H265DONReorderer is not safe for concurrent use.
type H265DONReorderer struct {
	window int64

	hasMax  bool
	maxExt  int64 // highest extended DON seen
	hasNext bool
	nextDon int64 // next DON to emit

	pending map[int64][]byte // complete NALUs waiting for their DON turn
	fus     map[h265FUKey]*h265FUAssembly

	stats H265DONReordererStats
}

// NewH265DONReorderer creates a reorderer holding at most window DON
// positions. window is clamped to [1, h265DONReordererMaxWindow]; a window of
// 1 disables reordering (only in-order NALUs are emitted).
func NewH265DONReorderer(window uint16) *H265DONReorderer {
	w := int64(window)
	if w < 1 {
		w = 1
	}
	if w > h265DONReordererMaxWindow {
		w = h265DONReordererMaxWindow
	}

	return &H265DONReorderer{
		window:  w,
		pending: make(map[int64][]byte),
		fus:     make(map[h265FUKey]*h265FUAssembly),
	}
}

// Stats returns a snapshot of the reorderer's disposition counters.
func (r *H265DONReorderer) Stats() H265DONReordererStats {
	return r.stats
}

// extendDON maps a 16-bit DONL onto the 32-bit extended DON space, tracking
// wraparound against the highest DON seen so far.
func (r *H265DONReorderer) extendDON(donl uint16) int64 {
	if !r.hasMax {
		r.hasMax = true
		r.maxExt = int64(donl)

		return r.maxExt
	}

	candidate := (r.maxExt &^ 0xFFFF) | int64(donl)
	switch {
	case candidate > r.maxExt+0x8000:
		candidate -= 0x10000
	case candidate < r.maxExt-0x8000:
		candidate += 0x10000
	}
	if candidate > r.maxExt {
		r.maxExt = candidate
	}

	return candidate
}

// insert buffers one complete NALU and returns the NALUs that become
// decodable, in DON order.
func (r *H265DONReorderer) insert(don int64, nalu []byte, emitted [][]byte) [][]byte {
	if !r.hasNext {
		r.hasNext = true
		r.nextDon = don
	}
	if don < r.nextDon {
		r.stats.DroppedLate++

		return emitted
	}
	if _, ok := r.pending[don]; ok {
		r.stats.DroppedDuplicates++

		return emitted
	}

	// Window overflow: declare every position older than don-window+1 lost.
	for don-r.nextDon >= r.window {
		emitted = r.emitNext(emitted)
	}

	r.pending[don] = nalu
	for len(r.pending) > 0 {
		if _, ok := r.pending[r.nextDon]; !ok {
			break
		}
		emitted = r.emitNext(emitted)
	}

	return emitted
}

// emitNext emits (or skips, if missing) the position nextDon and advances it.
func (r *H265DONReorderer) emitNext(emitted [][]byte) [][]byte {
	if nalu, ok := r.pending[r.nextDon]; ok {
		emitted = append(emitted, nalu)
		delete(r.pending, r.nextDon)
		r.stats.Emitted++
	} else {
		r.stats.DroppedOverflow++
	}
	r.nextDon++

	return emitted
}

// Push consumes one H265 RTP payload carrying DONL/DOND fields and returns
// the complete NALUs that become decodable, in extended DON order.
func (r *H265DONReorderer) Push(timestamp uint32, payload []byte) ([][]byte, error) {
	if len(payload) < h265NaluHeaderSize {
		return nil, errShortPacket
	}

	header := H265NALUHeader(binary.BigEndian.Uint16(payload[0:2]))

	switch {
	case header.IsFragmentationUnit():
		return r.pushFragmentationUnit(timestamp, payload)
	case header.IsAggregationPacket():
		return r.pushAggregationPacket(payload)
	case header.IsPACIPacket():
		return nil, errUnhandledNALUType
	default:
		single, err := parseH265SingleNalUnitPacket(payload, true)
		if err != nil {
			return nil, err
		}
		if single.donl == nil {
			return nil, errH265DONLRequired
		}

		return r.insert(r.extendDON(*single.donl), single.toAnnexB(nil), nil), nil
	}
}

func (r *H265DONReorderer) pushAggregationPacket(payload []byte) ([][]byte, error) {
	aggregation, err := parseH265AggregationPacket(payload, true)
	if err != nil {
		return nil, err
	}
	if aggregation.donl == nil {
		return nil, errH265DONLRequired
	}

	units, err := splitH265AggregationPacket(*aggregation)
	if err != nil {
		return nil, err
	}

	var emitted [][]byte
	for i := range units {
		if units[i].donl == nil {
			return nil, errH265DONLRequired
		}
		emitted = r.insert(r.extendDON(*units[i].donl), units[i].toAnnexB(nil), emitted)
	}

	return emitted, nil
}

func (r *H265DONReorderer) pushFragmentationUnit(timestamp uint32, payload []byte) ([][]byte, error) {
	if len(payload) < h265NaluHeaderSize+h265FragmentationUnitHeaderSize {
		return nil, errShortPacket
	}

	fuHeader := H265FragmentationUnitHeader(payload[2])
	if fuHeader.S() && fuHeader.E() {
		return nil, errH265SimultaneousFUStartAndEnd
	}

	// Only the start unit of a fragmented NALU carries a DONL field.
	fragment, err := parseH265FragmentationPacket(payload, fuHeader.S())
	if err != nil {
		return nil, err
	}

	key := h265FUKey{timestamp: timestamp, layerID: fragment.payloadHeader.LayerID()}

	if fuHeader.S() {
		if fragment.donl == nil {
			return nil, errH265DONLRequired
		}
		if _, ok := r.fus[key]; ok {
			// A new start unit supersedes the incomplete assembly.
			r.stats.DroppedIncomplete++
		}
		part := make([]byte, len(fragment.payload))
		copy(part, fragment.payload)
		r.fus[key] = &h265FUAssembly{
			don:           r.extendDON(*fragment.donl),
			payloadHeader: fragment.payloadHeader,
			fuType:        fuHeader.FuType(),
			parts:         [][]byte{part},
		}

		return nil, nil
	}

	assembly, ok := r.fus[key]
	if !ok {
		// A fragment without a start unit is dropped.
		r.stats.DroppedIncomplete++

		return nil, nil
	}

	part := make([]byte, len(fragment.payload))
	copy(part, fragment.payload)
	assembly.parts = append(assembly.parts, part)

	if !fuHeader.E() {
		return nil, nil
	}
	delete(r.fus, key)

	size := h265NaluHeaderSize
	for _, p := range assembly.parts {
		size += len(p)
	}
	nalu := make([]byte, 0, len(annexbNALUStartCode)+size)
	nalu = append(nalu, annexbNALUStartCode...)
	rebuilt := rebuildH265FragmentationPacketHeader(
		assembly.payloadHeader,
		H265FragmentationUnitHeader(assembly.fuType),
	)
	nalu = binary.BigEndian.AppendUint16(nalu, uint16(rebuilt))
	for _, p := range assembly.parts {
		nalu = append(nalu, p...)
	}

	return r.insert(assembly.don, nalu, nil), nil
}

// Flush closes the reorderer: it returns every buffered complete NALU in DON
// order, drops all incomplete FU assemblies (counted in DroppedIncomplete)
// and resets the reorderer to its initial state.
func (r *H265DONReorderer) Flush() [][]byte {
	var emitted [][]byte
	if len(r.pending) > 0 {
		dons := make([]int64, 0, len(r.pending))
		for don := range r.pending {
			dons = append(dons, don)
		}
		slices.Sort(dons)
		for _, don := range dons {
			emitted = append(emitted, r.pending[don])
			r.stats.Emitted++
		}
	}

	r.stats.DroppedIncomplete += uint64(len(r.fus)) // nolint: gosec // G115 map length fits

	r.pending = make(map[int64][]byte)
	r.fus = make(map[h265FUKey]*h265FUAssembly)
	r.hasMax = false
	r.maxExt = 0
	r.hasNext = false
	r.nextDon = 0

	return emitted
}
