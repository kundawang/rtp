// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOriginalPayloadType = 96
	testRTXPayloadType      = 97
	testOriginalSSRC        = 0xAABBCCDD
	testRTXSSRC             = 0x11223344
)

func testMapping() RTXMapping {
	return RTXMapping{
		OriginalPayloadType: testOriginalPayloadType,
		RTXPayloadType:      testRTXPayloadType,
		OriginalSSRC:        testOriginalSSRC,
		RTXSSRC:             testRTXSSRC,
	}
}

func testPacket(sequence uint16, marker bool, payload []byte) *Packet {
	return &Packet{
		Header: Header{
			Version:        2,
			Marker:         marker,
			PayloadType:    testOriginalPayloadType,
			SequenceNumber: sequence,
			Timestamp:      0x12345678,
			SSRC:           testOriginalSSRC,
			CSRC:           []uint32{0xDEADBEEF},
		},
		Payload: payload,
	}
}

func TestRTXMappingValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, testMapping().Validate())
	})

	t.Run("same payload type", func(t *testing.T) {
		mapping := testMapping()
		mapping.RTXPayloadType = mapping.OriginalPayloadType
		assert.ErrorIs(t, mapping.Validate(), ErrRTXInvalidMapping)
	})

	t.Run("same SSRC", func(t *testing.T) {
		mapping := testMapping()
		mapping.RTXSSRC = mapping.OriginalSSRC
		assert.ErrorIs(t, mapping.Validate(), ErrRTXInvalidMapping)
	})
}

func TestRTXNewEncapsulatorConfig(t *testing.T) {
	t.Run("invalid mapping", func(t *testing.T) {
		mapping := testMapping()
		mapping.RTXPayloadType = mapping.OriginalPayloadType

		_, err := NewRTXEncapsulator(mapping, 0, 4)
		assert.ErrorIs(t, err, ErrRTXInvalidMapping)
	})

	t.Run("zero cache size", func(t *testing.T) {
		_, err := NewRTXEncapsulator(testMapping(), 0, 0)
		assert.ErrorIs(t, err, ErrRTXInvalidConfig)
	})

	t.Run("negative cache size", func(t *testing.T) {
		_, err := NewRTXEncapsulator(testMapping(), 0, -1)
		assert.ErrorIs(t, err, ErrRTXInvalidConfig)
	})

	t.Run("cache size above uint16 range", func(t *testing.T) {
		_, err := NewRTXEncapsulator(testMapping(), 0, 65536)
		assert.ErrorIs(t, err, ErrRTXInvalidConfig)
	})
}

func TestRTXNewDecapsulatorConfig(t *testing.T) {
	t.Run("no mappings", func(t *testing.T) {
		_, err := NewRTXDecapsulator()
		assert.ErrorIs(t, err, ErrRTXInvalidConfig)
	})

	t.Run("duplicated mapping", func(t *testing.T) {
		_, err := NewRTXDecapsulator(testMapping(), testMapping())
		assert.ErrorIs(t, err, ErrRTXInvalidMapping)
	})

	t.Run("invalid mapping", func(t *testing.T) {
		mapping := testMapping()
		mapping.OriginalSSRC = mapping.RTXSSRC

		_, err := NewRTXDecapsulator(mapping)
		assert.ErrorIs(t, err, ErrRTXInvalidMapping)
	})

	t.Run("valid", func(t *testing.T) {
		decapsulator, err := NewRTXDecapsulator(testMapping())
		require.NoError(t, err)
		assert.Len(t, decapsulator.mappings, 1)
	})
}

func TestRTXEncapsulate(t *testing.T) {
	encapsulator, err := NewRTXEncapsulator(testMapping(), 100, 8)
	require.NoError(t, err)

	t.Run("wrong payload type", func(t *testing.T) {
		packet := testPacket(1, true, []byte{0x01})
		packet.PayloadType = 95

		_, err := encapsulator.Encapsulate(packet)
		assert.ErrorIs(t, err, ErrRTXMappingNotFound)
	})

	t.Run("wrong SSRC", func(t *testing.T) {
		packet := testPacket(1, true, []byte{0x01})
		packet.SSRC = 1

		_, err := encapsulator.Encapsulate(packet)
		assert.ErrorIs(t, err, ErrRTXMappingNotFound)
	})

	t.Run("nil packet", func(t *testing.T) {
		_, err := encapsulator.Encapsulate(nil)
		assert.ErrorIs(t, err, ErrRTXEmptyPayload)
	})

	t.Run("empty payload", func(t *testing.T) {
		_, err := encapsulator.Encapsulate(testPacket(1, true, nil))
		assert.ErrorIs(t, err, ErrRTXEmptyPayload)
	})

	t.Run("independent sequence space and preserved header fields", func(t *testing.T) {
		packet := testPacket(42, true, []byte{0x01, 0x02, 0x03})
		require.NoError(t, packet.Header.SetExtension(3, []byte{0xAB, 0xCD}))

		originalBytes, err := packet.Marshal()
		require.NoError(t, err)

		rtxPacket, err := encapsulator.Encapsulate(packet)
		require.NoError(t, err)

		// RTX packet uses the RTX payload type, SSRC and its own sequence number.
		assert.Equal(t, uint8(testRTXPayloadType), rtxPacket.PayloadType)
		assert.Equal(t, uint32(testRTXSSRC), rtxPacket.SSRC)
		assert.Equal(t, uint16(100), rtxPacket.SequenceNumber)

		// Timestamp, marker, CSRC and header extensions are retained.
		assert.Equal(t, packet.Timestamp, rtxPacket.Timestamp)
		assert.True(t, rtxPacket.Marker)
		assert.Equal(t, []uint32{0xDEADBEEF}, rtxPacket.CSRC)
		assert.Equal(t, []byte{0xAB, 0xCD}, rtxPacket.GetExtension(3))

		// The payload is OSN followed by the untouched original payload.
		assert.Equal(t, []byte{0x00, 0x2A, 0x01, 0x02, 0x03}, rtxPacket.Payload)
		assert.False(t, rtxPacket.Padding)
		assert.Zero(t, rtxPacket.Header.PaddingSize)

		// The RTX sequence number advances independently of the original one.
		rtxPacket2, err := encapsulator.Encapsulate(testPacket(43, false, []byte{0x04}))
		require.NoError(t, err)
		assert.Equal(t, uint16(101), rtxPacket2.SequenceNumber)
		assert.False(t, rtxPacket2.Marker)

		// The original packet is not modified and still marshals identically.
		originalBytesAfter, err := packet.Marshal()
		require.NoError(t, err)
		assert.Equal(t, originalBytes, originalBytesAfter)

		// Mutating the RTX packet must not reach the original packet.
		rtxPacket.Payload[2] = 0xFF
		assert.Equal(t, byte(0x01), packet.Payload[0])
	})
}

func TestRTXEncapsulateSequenceWraparound(t *testing.T) {
	// The RTX sequence space starts at 65535 and must wrap back to 0.
	encapsulator, err := NewRTXEncapsulator(testMapping(), 65535, 4)
	require.NoError(t, err)

	first, err := encapsulator.Encapsulate(testPacket(10, true, []byte{0x01}))
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), first.SequenceNumber)

	second, err := encapsulator.Encapsulate(testPacket(11, true, []byte{0x02}))
	require.NoError(t, err)
	assert.Equal(t, uint16(0), second.SequenceNumber)

	third, err := encapsulator.Encapsulate(testPacket(12, true, []byte{0x03}))
	require.NoError(t, err)
	assert.Equal(t, uint16(1), third.SequenceNumber)
}

// TestRTXGoldenBytesCrossingWraparound checks the exact on-wire bytes of RTX
// packets whose original sequence numbers cross the 65535 boundary, and that
// decapsulation restores the original packets byte for byte.
func TestRTXGoldenBytesCrossingWraparound(t *testing.T) {
	encapsulator, err := NewRTXEncapsulator(testMapping(), 65535, 8)
	require.NoError(t, err)
	decapsulator, err := NewRTXDecapsulator(testMapping())
	require.NoError(t, err)

	originals := []*Packet{
		testPacket(65534, true, []byte{0x01, 0x02, 0x03}),
		testPacket(65535, false, []byte{0x04, 0x05}),
		testPacket(0, true, []byte{0x06}),
	}

	wantRTX := [][]byte{
		// V=2, CC=1 (one CSRC), M=1, PT=97; RTX seq 65535; RTX SSRC; OSN=65534; payload.
		{
			0x81, 0xE1, 0xFF, 0xFF, 0x12, 0x34, 0x56, 0x78,
			0x11, 0x22, 0x33, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
			0xFF, 0xFE, 0x01, 0x02, 0x03,
		},
		// M=0; RTX seq 0 (wrapped); OSN=65535.
		{
			0x81, 0x61, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
			0x11, 0x22, 0x33, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
			0xFF, 0xFF, 0x04, 0x05,
		},
		// M=1; RTX seq 1; OSN=0.
		{
			0x81, 0xE1, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78,
			0x11, 0x22, 0x33, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
			0x00, 0x00, 0x06,
		},
	}

	for i, original := range originals {
		originalRaw, marshalErr := original.Marshal()
		require.NoError(t, marshalErr)

		rtxPacket, encapErr := encapsulator.Encapsulate(original)
		require.NoError(t, encapErr)

		rtxRaw, marshalErr := rtxPacket.Marshal()
		require.NoError(t, marshalErr)
		assert.Equal(t, wantRTX[i], rtxRaw, "RTX packet %d wire bytes", i)

		// Unmarshal the wire bytes again before restoring the original packet.
		parsedRTX := &Packet{}
		require.NoError(t, parsedRTX.Unmarshal(rtxRaw))

		restored, decapErr := decapsulator.Decapsulate(parsedRTX)
		require.NoError(t, decapErr)

		restoredRaw, marshalErr := restored.Marshal()
		require.NoError(t, marshalErr)
		assert.Equal(t, originalRaw, restoredRaw, "restored packet %d wire bytes", i)
		assert.Equal(t, original, restored)

		// The RTX packet handed to the decapsulator is left untouched.
		rtxRawAfter, marshalErr := parsedRTX.Marshal()
		require.NoError(t, marshalErr)
		assert.Equal(t, rtxRaw, rtxRawAfter)
	}
}

func TestRTXDecapsulate(t *testing.T) {
	decapsulator, err := NewRTXDecapsulator(testMapping())
	require.NoError(t, err)
	encapsulator, err := NewRTXEncapsulator(testMapping(), 7, 4)
	require.NoError(t, err)

	t.Run("nil packet", func(t *testing.T) {
		_, err := decapsulator.Decapsulate(nil)
		assert.ErrorIs(t, err, ErrRTXMappingNotFound)
	})

	t.Run("unknown mapping", func(t *testing.T) {
		rtxPacket := testPacket(1, true, []byte{0x00, 0x01, 0x02})
		rtxPacket.PayloadType = 98
		rtxPacket.SSRC = testRTXSSRC

		_, err := decapsulator.Decapsulate(rtxPacket)
		assert.ErrorIs(t, err, ErrRTXMappingNotFound)
	})

	t.Run("payload shorter than OSN", func(t *testing.T) {
		rtxPacket := testPacket(1, true, []byte{0x00})
		rtxPacket.PayloadType = testRTXPayloadType
		rtxPacket.SSRC = testRTXSSRC

		_, err := decapsulator.Decapsulate(rtxPacket)
		assert.ErrorIs(t, err, ErrRTXEmptyPayload)
	})

	t.Run("payload with only the OSN field is an empty original payload", func(t *testing.T) {
		rtxPacket := testPacket(1, true, []byte{0x12, 0x34})
		rtxPacket.PayloadType = testRTXPayloadType
		rtxPacket.SSRC = testRTXSSRC

		restored, err := decapsulator.Decapsulate(rtxPacket)
		require.NoError(t, err)
		assert.Equal(t, uint16(0x1234), restored.SequenceNumber)
		assert.Empty(t, restored.Payload)
		assert.Equal(t, uint8(testOriginalPayloadType), restored.PayloadType)
		assert.Equal(t, uint32(testOriginalSSRC), restored.SSRC)
	})

	t.Run("roundtrip restores the original packet", func(t *testing.T) {
		original := testPacket(555, true, []byte{0xAA, 0xBB, 0xCC, 0xDD})
		require.NoError(t, original.SetExtension(5, []byte{0x7F}))

		rtxPacket, err := encapsulator.Encapsulate(original)
		require.NoError(t, err)

		restored, err := decapsulator.Decapsulate(rtxPacket)
		require.NoError(t, err)

		assert.Equal(t, original, restored)
		assert.Equal(t, []byte{0x7F}, restored.GetExtension(5))
		assert.True(t, restored.Marker)
	})

	t.Run("multiple mappings", func(t *testing.T) {
		other := RTXMapping{
			OriginalPayloadType: 98,
			RTXPayloadType:      99,
			OriginalSSRC:        0x01020304,
			RTXSSRC:             0x05060708,
		}
		multi, err := NewRTXDecapsulator(testMapping(), other)
		require.NoError(t, err)

		rtxPacket := testPacket(9, false, []byte{0x00, 0x09, 0x10})
		rtxPacket.PayloadType = other.RTXPayloadType
		rtxPacket.SSRC = other.RTXSSRC

		restored, err := multi.Decapsulate(rtxPacket)
		require.NoError(t, err)
		assert.Equal(t, uint8(98), restored.PayloadType)
		assert.Equal(t, uint32(0x01020304), restored.SSRC)
		assert.Equal(t, uint16(9), restored.SequenceNumber)
		assert.Equal(t, []byte{0x10}, restored.Payload)
	})
}

func TestRTXRetransmitCache(t *testing.T) {
	encapsulator, err := NewRTXEncapsulator(testMapping(), 500, 3)
	require.NoError(t, err)

	t.Run("empty cache", func(t *testing.T) {
		_, _, err := encapsulator.Retransmit(1)
		assert.ErrorIs(t, err, ErrRTXPacketNotRetransmitted)
	})

	t.Run("store rejects wrong mapping", func(t *testing.T) {
		packet := testPacket(1, true, []byte{0x01})
		packet.PayloadType = 95
		assert.ErrorIs(t, encapsulator.Store(packet), ErrRTXMappingNotFound)
	})

	t.Run("store rejects nil packet", func(t *testing.T) {
		assert.ErrorIs(t, encapsulator.Store(nil), ErrRTXEmptyPayload)
	})

	// Fill a three-slot cache with sequence numbers crossing the wrap point.
	for _, sequence := range []uint16{65534, 65535, 0} {
		require.NoError(t, encapsulator.Store(testPacket(sequence, true, []byte{byte(sequence)})))
	}
	t.Run("first retransmission is not duplicated", func(t *testing.T) {
		rtxPacket, duplicated, err := encapsulator.Retransmit(65535)
		require.NoError(t, err)
		assert.False(t, duplicated)
		assert.Equal(t, uint16(500), rtxPacket.SequenceNumber)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF}, rtxPacket.Payload)
	})

	t.Run("second retransmission is duplicated with a fresh RTX sequence", func(t *testing.T) {
		rtxPacket, duplicated, err := encapsulator.Retransmit(65535)
		require.NoError(t, err)
		assert.True(t, duplicated)
		assert.Equal(t, uint16(501), rtxPacket.SequenceNumber)
	})

	t.Run("storing past the cache size evicts the oldest packet", func(t *testing.T) {
		require.NoError(t, encapsulator.Store(testPacket(1, true, []byte{0x01})))

		// 65534 was the oldest and is evicted.
		_, _, err := encapsulator.Retransmit(65534)
		assert.ErrorIs(t, err, ErrRTXPacketNotRetransmitted)

		// The surviving window (65535, 0, 1) still retransmits, including wrap.
		for _, sequence := range []uint16{65535, 0, 1} {
			rtxPacket, _, err := encapsulator.Retransmit(sequence)
			require.NoError(t, err)
			assert.Equal(t, sequence, binary.BigEndian.Uint16(rtxPacket.Payload[:rtxPayloadLen]))
		}
	})

	t.Run("never stored sequence numbers fail across the wrap point", func(t *testing.T) {
		// Older than the window.
		_, _, err := encapsulator.Retransmit(65533)
		assert.ErrorIs(t, err, ErrRTXPacketNotRetransmitted)

		// Newer than anything stored.
		_, _, err = encapsulator.Retransmit(2)
		assert.ErrorIs(t, err, ErrRTXPacketNotRetransmitted)
	})
}
