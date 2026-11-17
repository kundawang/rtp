// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// h265DONSinglePacket builds a single NAL unit packet carrying a DONL field.
func h265DONSinglePacket(donl uint16, pType uint8, payload []byte) []byte {
	nalu := createTestH265NALU(pType, payload)
	out := make([]byte, 0, len(nalu)+h265NaluDonlSize)
	out = append(out, nalu[:h265NaluHeaderSize]...)
	out = binary.BigEndian.AppendUint16(out, donl)

	return append(out, nalu[h265NaluHeaderSize:]...)
}

// h265DONFUPacket builds one FU packet. donl must be non-nil exactly for the
// start unit, the only FU packet that carries a DONL field.
func h265DONFUPacket(layerID uint8, donl *uint16, start, end bool, fuType uint8, payload []byte) []byte {
	header := createTestH265Header(h265NaluFragmentationUnitType, layerID, 1, false)
	fuHeader := fuType & 0b00111111
	if start {
		fuHeader |= 0b10000000
	}
	if end {
		fuHeader |= 0b01000000
	}

	out := make([]byte, 0, h265NaluHeaderSize+1+h265NaluDonlSize+len(payload))
	out = binary.BigEndian.AppendUint16(out, uint16(header))
	out = append(out, fuHeader)
	if donl != nil {
		out = binary.BigEndian.AppendUint16(out, *donl)
	}

	return append(out, payload...)
}

// h265DONAggregationPacket builds an AP carrying the given NALUs. donds[i] is
// the DOND field preceding nalus[i+1]; the derived DONL of unit i+1 is the
// previous unit's DONL plus donds[i]+1 (mod 2^16).
func h265DONAggregationPacket(donl uint16, nalus [][]byte, donds []uint8) []byte {
	out := make([]byte, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(createTestH265Header(h265NaluAggregationPacketType, 0, 1, false)))
	out = binary.BigEndian.AppendUint16(out, donl)
	for i, nalu := range nalus {
		if i > 0 {
			out = append(out, donds[i-1])
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(nalu))) // nolint: gosec // test data
		out = append(out, nalu...)
	}

	return out
}

func h265DONPtr(v uint16) *uint16 {
	return &v
}

func TestH265DONReorderer_InOrderSingles(t *testing.T) {
	r := NewH265DONReorderer(8)

	for donl := uint16(0); donl < 5; donl++ {
		emitted, err := r.Push(900, h265DONSinglePacket(donl, 1, []byte{byte(donl)})) // nolint: gosec // test data
		require.NoError(t, err)
		require.Len(t, emitted, 1)
		assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{byte(donl)})), emitted[0]) // nolint: gosec // test data
	}

	assert.Equal(t, H265DONReordererStats{Emitted: 5}, r.Stats())
}

func TestH265DONReorderer_ReordersWithinWindow(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(donl uint16) [][]byte {
		emitted, err := r.Push(900, h265DONSinglePacket(donl, 1, []byte{byte(donl)})) // nolint: gosec // test data
		require.NoError(t, err)

		return emitted
	}

	require.Len(t, push(0), 1)
	assert.Empty(t, push(2))
	assert.Empty(t, push(3))

	emitted := push(1)
	require.Len(t, emitted, 3)
	for i, donl := range []uint16{1, 2, 3} {
		assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{byte(donl)})), emitted[i]) // nolint: gosec // test data
	}

	assert.Equal(t, H265DONReordererStats{Emitted: 4}, r.Stats())
}

func TestH265DONReorderer_Wraparound(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(donl uint16) [][]byte {
		emitted, err := r.Push(900, h265DONSinglePacket(donl, 1, []byte{byte(donl)})) // nolint: gosec // test data
		require.NoError(t, err)

		return emitted
	}

	// In-order across the 16-bit DONL wrap point.
	for _, donl := range []uint16{65534, 65535, 0, 1} {
		emitted := push(donl)
		require.Len(t, emitted, 1)
		assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{byte(donl)})), emitted[0]) // nolint: gosec // test data
	}

	// Out-of-order across the wrap point: 0 arrives before 65535.
	assert.Empty(t, push(3))
	emitted := push(2)
	require.Len(t, emitted, 2)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{2})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{3})), emitted[1])

	assert.Equal(t, H265DONReordererStats{Emitted: 6}, r.Stats())
}

func TestH265DONReorderer_AggregationExpandsInDONOrder(t *testing.T) {
	r := NewH265DONReorderer(8)

	// AP carrying DONs 10, 11 and 13 (DOND=1 skips DON 12).
	ap := h265DONAggregationPacket(10, [][]byte{
		createTestH265NALU(1, []byte{0xA0}),
		createTestH265NALU(1, []byte{0xA1}),
		createTestH265NALU(1, []byte{0xA3}),
	}, []uint8{0, 1})

	emitted, err := r.Push(900, ap)
	require.NoError(t, err)
	require.Len(t, emitted, 2)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xA0})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xA1})), emitted[1])

	// The skipped DON 12 arrives late and releases DON 13.
	emitted, err = r.Push(900, h265DONSinglePacket(12, 1, []byte{0xA2}))
	require.NoError(t, err)
	require.Len(t, emitted, 2)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xA2})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xA3})), emitted[1])

	assert.Equal(t, H265DONReordererStats{Emitted: 4}, r.Stats())
}

func TestH265DONReorderer_FUReassembly(t *testing.T) {
	r := NewH265DONReorderer(8)

	emitted, err := r.Push(900, h265DONSinglePacket(6, 1, []byte{0x06}))
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	emitted, err = r.Push(901, h265DONFUPacket(0, h265DONPtr(7), true, false, 19, []byte{0xF1, 0xF2}))
	require.NoError(t, err)
	assert.Empty(t, emitted)

	emitted, err = r.Push(901, h265DONFUPacket(0, nil, false, false, 19, []byte{0xF3}))
	require.NoError(t, err)
	assert.Empty(t, emitted)

	emitted, err = r.Push(901, h265DONFUPacket(0, nil, false, true, 19, []byte{0xF4, 0xF5}))
	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t,
		createTestH265AnnexB(createTestH265NALU(19, []byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5})),
		emitted[0],
	)

	assert.Equal(t, H265DONReordererStats{Emitted: 2}, r.Stats())
}

func TestH265DONReorderer_MixedAPAndFU(t *testing.T) {
	r := NewH265DONReorderer(8)

	// A fragmented NALU with DON 22 starts before the AP carrying DONs 20-21
	// arrives; the FU start must not anchor the emission point.
	emitted, err := r.Push(901, h265DONFUPacket(0, h265DONPtr(22), true, false, 1, []byte{0xB0}))
	require.NoError(t, err)
	assert.Empty(t, emitted)

	ap := h265DONAggregationPacket(20, [][]byte{
		createTestH265NALU(1, []byte{0xC0}),
		createTestH265NALU(1, []byte{0xC1}),
	}, []uint8{0})
	emitted, err = r.Push(900, ap)
	require.NoError(t, err)
	require.Len(t, emitted, 2)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xC0})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xC1})), emitted[1])

	emitted, err = r.Push(901, h265DONFUPacket(0, nil, false, true, 1, []byte{0xB1}))
	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0xB0, 0xB1})), emitted[0])

	assert.Equal(t, H265DONReordererStats{Emitted: 3}, r.Stats())
}

func TestH265DONReorderer_CrossWrapMixedSequence(t *testing.T) {
	r := NewH265DONReorderer(8)

	var emitted [][]byte
	push := func(timestamp uint32, payload []byte) {
		out, err := r.Push(timestamp, payload)
		require.NoError(t, err)
		emitted = append(emitted, out...)
	}

	push(900, h265DONSinglePacket(65533, 1, []byte{0x01}))
	push(901, h265DONFUPacket(0, h265DONPtr(65534), true, false, 19, []byte{0xF1}))
	// AP whose DOND chain crosses the wrap point: DONs 65535 and 0.
	push(902, h265DONAggregationPacket(65535, [][]byte{
		createTestH265NALU(1, []byte{0x02}),
		createTestH265NALU(1, []byte{0x03}),
	}, []uint8{0}))
	push(901, h265DONFUPacket(0, nil, false, true, 19, []byte{0xF2}))
	push(903, h265DONSinglePacket(2, 1, []byte{0x05}))
	push(903, h265DONSinglePacket(1, 1, []byte{0x04}))

	require.Len(t, emitted, 6)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x01})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(19, []byte{0xF1, 0xF2})), emitted[1])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x02})), emitted[2])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x03})), emitted[3])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x04})), emitted[4])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x05})), emitted[5])

	assert.Equal(t, H265DONReordererStats{Emitted: 6}, r.Stats())
}

func TestH265DONReorderer_FUIsolationByTimestampAndLayer(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(timestamp uint32, payload []byte) [][]byte {
		emitted, err := r.Push(timestamp, payload)
		require.NoError(t, err)

		return emitted
	}

	// Two fragmented NALUs interleaved on different timestamps.
	assert.Empty(t, push(1, h265DONFUPacket(0, h265DONPtr(30), true, false, 1, []byte{0x01})))
	assert.Empty(t, push(2, h265DONFUPacket(0, h265DONPtr(31), true, false, 1, []byte{0x02})))

	emitted := push(1, h265DONFUPacket(0, nil, false, true, 1, []byte{0x03}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x01, 0x03})), emitted[0])

	emitted = push(2, h265DONFUPacket(0, nil, false, true, 1, []byte{0x04}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x02, 0x04})), emitted[0])

	// Two fragmented NALUs interleaved on the same timestamp but different layers.
	assert.Empty(t, push(7, h265DONFUPacket(0, h265DONPtr(32), true, false, 1, []byte{0x0A})))
	assert.Empty(t, push(7, h265DONFUPacket(1, h265DONPtr(33), true, false, 1, []byte{0x0B})))

	emitted = push(7, h265DONFUPacket(0, nil, false, true, 1, []byte{0x0C}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALUWithLayer(1, 0, []byte{0x0A, 0x0C})), emitted[0])

	emitted = push(7, h265DONFUPacket(1, nil, false, true, 1, []byte{0x0D}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALUWithLayer(1, 1, []byte{0x0B, 0x0D})), emitted[0])

	assert.Equal(t, H265DONReordererStats{Emitted: 4}, r.Stats())
}

func TestH265DONReorderer_DuplicateAndLateDrops(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(donl uint16) [][]byte {
		emitted, err := r.Push(900, h265DONSinglePacket(donl, 1, []byte{byte(donl)})) // nolint: gosec // test data
		require.NoError(t, err)

		return emitted
	}

	require.Len(t, push(0), 1)
	assert.Empty(t, push(2))
	assert.Empty(t, push(2)) // duplicate of a buffered DON
	assert.Empty(t, push(0)) // already emitted

	stats := r.Stats()
	assert.Equal(t, uint64(1), stats.DroppedDuplicates)
	assert.Equal(t, uint64(1), stats.DroppedLate)

	require.Len(t, push(1), 2)
	assert.Equal(t, uint64(3), r.Stats().Emitted)
}

func TestH265DONReorderer_WindowOverflow(t *testing.T) {
	r := NewH265DONReorderer(2)

	push := func(donl uint16) [][]byte {
		emitted, err := r.Push(900, h265DONSinglePacket(donl, 1, []byte{byte(donl)})) // nolint: gosec // test data
		require.NoError(t, err)

		return emitted
	}

	require.Len(t, push(10), 1)

	// DON 13 is more than the window ahead of the missing DON 11: the gap is
	// declared lost and skipped.
	assert.Empty(t, push(13))
	assert.Equal(t, uint64(1), r.Stats().DroppedOverflow)

	emitted := push(12)
	require.Len(t, emitted, 2)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{12})), emitted[0])
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{13})), emitted[1])

	// The skipped DON 11 is dropped as late when it finally arrives.
	assert.Empty(t, push(11))
	assert.Equal(t, uint64(1), r.Stats().DroppedLate)
	assert.Equal(t, uint64(3), r.Stats().Emitted)
}

func TestH265DONReorderer_MissingFragments(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(timestamp uint32, payload []byte) [][]byte {
		emitted, err := r.Push(timestamp, payload)
		require.NoError(t, err)

		return emitted
	}

	// A new start unit supersedes the incomplete assembly for DON 40.
	assert.Empty(t, push(5, h265DONFUPacket(0, h265DONPtr(40), true, false, 1, []byte{0x01})))
	assert.Empty(t, push(5, h265DONFUPacket(0, h265DONPtr(41), true, false, 1, []byte{0x02})))
	assert.Equal(t, uint64(1), r.Stats().DroppedIncomplete)

	// The second assembly completes and is emitted whole.
	assert.Empty(t, push(5, h265DONFUPacket(0, nil, false, false, 1, []byte{0x03})))
	emitted := push(5, h265DONFUPacket(0, nil, false, true, 1, []byte{0x04}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x02, 0x03, 0x04})), emitted[0])

	// A fragment without a start unit is dropped, not an error.
	assert.Empty(t, push(9, h265DONFUPacket(0, nil, false, true, 1, []byte{0x05})))
	assert.Equal(t, uint64(2), r.Stats().DroppedIncomplete)
}

func TestH265DONReorderer_FlushResidual(t *testing.T) {
	r := NewH265DONReorderer(8)

	push := func(timestamp uint32, payload []byte) [][]byte {
		emitted, err := r.Push(timestamp, payload)
		require.NoError(t, err)

		return emitted
	}

	require.Len(t, push(900, h265DONSinglePacket(50, 1, []byte{0x50})), 1)
	assert.Empty(t, push(900, h265DONSinglePacket(52, 1, []byte{0x52}))) // gap at DON 51
	assert.Empty(t, push(901, h265DONFUPacket(0, h265DONPtr(53), true, false, 1, []byte{0x53})))

	// Flush emits the buffered NALU despite the gap and drops the incomplete FU.
	flushed := r.Flush()
	require.Len(t, flushed, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x52})), flushed[0])

	stats := r.Stats()
	assert.Equal(t, uint64(2), stats.Emitted)
	assert.Equal(t, uint64(1), stats.DroppedIncomplete)

	// The reorderer is reset and can anchor on a fresh stream.
	emitted := push(500, h265DONSinglePacket(0, 1, []byte{0x00}))
	require.Len(t, emitted, 1)
	assert.Equal(t, createTestH265AnnexB(createTestH265NALU(1, []byte{0x00})), emitted[0])
}

func TestH265DONReorderer_Errors(t *testing.T) {
	r := NewH265DONReorderer(8)

	// Short packet.
	_, err := r.Push(900, []byte{0x00})
	assert.ErrorIs(t, err, errShortPacket)

	// Single NALU too short to carry its DONL field.
	_, err = r.Push(900, createTestH265NALU(1, []byte{0x01}))
	assert.ErrorIs(t, err, errShortPacket)

	// PACI packets are not handled by the reorderer.
	paci := make([]byte, 0)
	paci = binary.BigEndian.AppendUint16(paci, uint16(createTestH265Header(h265NaluPACIPacketType, 0, 1, false)))
	_, err = r.Push(900, paci)
	assert.ErrorIs(t, err, errUnhandledNALUType)

	// A FU packet with both S and E set is invalid.
	_, err = r.Push(900, h265DONFUPacket(0, h265DONPtr(1), true, true, 1, []byte{0x01}))
	assert.ErrorIs(t, err, errH265SimultaneousFUStartAndEnd)

	// Truncated aggregation packet.
	ap := h265DONAggregationPacket(1, [][]byte{
		createTestH265NALU(1, []byte{0x01}),
		createTestH265NALU(1, []byte{0x02}),
	}, []uint8{0})
	_, err = r.Push(900, ap[:len(ap)-1])
	assert.ErrorIs(t, err, errShortPacket)

	// Errors leave the reorderer usable.
	emitted, err := r.Push(900, h265DONSinglePacket(0, 1, []byte{0x00}))
	require.NoError(t, err)
	require.Len(t, emitted, 1)
}

func TestH265DONReorderer_WindowClamping(t *testing.T) {
	assert.Equal(t, int64(1), NewH265DONReorderer(0).window)
	assert.Equal(t, int64(h265DONReordererMaxWindow), NewH265DONReorderer(0xFFFF).window)
}
