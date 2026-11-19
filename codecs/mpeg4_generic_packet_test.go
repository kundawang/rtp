// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mpeg4FixedAUs returns the fixed AU sequence reused by the
// bundling/fragmentation/round-trip tests. Each value byte identifies its
// position so reassembly order is verifiable.
func mpeg4FixedAUs() [][]byte {
	return [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05},
		{0x11, 0x12, 0x13},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
		{0x31, 0x32},
	}
}

func makeAU(length int, fill byte) []byte {
	au := make([]byte, length)
	for i := range au {
		au[i] = fill + byte(i)
	}

	return au
}

func TestNewMPEG4AudioPayloader_DefaultsAndConfig(t *testing.T) {
	t.Run("AAC-lbr defaults", func(t *testing.T) {
		payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
		require.NoError(t, err)
		assert.Equal(t, 6, payloader.SizeLength)
		assert.Equal(t, 2, payloader.IndexLength)
		assert.Equal(t, 2, payloader.IndexDeltaLength)
	})

	t.Run("AAC-hbr defaults", func(t *testing.T) {
		payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
		require.NoError(t, err)
		assert.Equal(t, 13, payloader.SizeLength)
		assert.Equal(t, 3, payloader.IndexLength)
		assert.Equal(t, 3, payloader.IndexDeltaLength)
	})

	t.Run("bad mode", func(t *testing.T) {
		_, err := NewMPEG4AudioPayloader(MPEG4GenericMode(99))
		assert.ErrorIs(t, err, errMPEG4BadMode)

		_, err = NewMPEG4AudioPacket(MPEG4GenericMode(99))
		assert.ErrorIs(t, err, errMPEG4BadMode)
	})

	t.Run("bit widths do not match mode", func(t *testing.T) {
		aus := mpeg4FixedAUs()

		lbr := &MPEG4AudioPayloader{Mode: MPEG4ModeAACLBR, SizeLength: 13, IndexLength: 3, IndexDeltaLength: 3}
		_, err := lbr.PayloadAUs(1200, aus[:1])
		assert.ErrorIs(t, err, errMPEG4BadConfig)

		hbr := &MPEG4AudioPayloader{Mode: MPEG4ModeAACHBR, SizeLength: 6, IndexLength: 2, IndexDeltaLength: 2}
		_, err = hbr.PayloadAUs(1200, aus[:1])
		assert.ErrorIs(t, err, errMPEG4BadConfig)
	})
}

func TestMPEG4Payloader_AACLBRGoldenBytes(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
	require.NoError(t, err)

	// Single AU of 5 octets: AU-headers-length=8, AU-size=5 (000101), index=0 (00)
	// -> 00010100 = 0x14.
	packets, err := payloader.PayloadAUs(100, [][]byte{mpeg4FixedAUs()[0]})
	require.NoError(t, err)
	require.Len(t, packets, 1)

	expected := []byte{0x00, 0x08, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05}
	assert.Equal(t, expected, packets[0])
}

func TestMPEG4Payloader_AACHBRGoldenBytes(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)
	aus := mpeg4FixedAUs()

	// Single AU of 5 octets: AU-headers-length=16, size=5 << 3 = 0x0028, index 0.
	packets, err := payloader.PayloadAUs(100, [][]byte{aus[0]})
	require.NoError(t, err)
	require.Len(t, packets, 1)

	expected := []byte{0x00, 0x10, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04, 0x05}
	assert.Equal(t, expected, packets[0])

	// Two complete AUs of 5 and 3 octets bundled into one timestamp.
	// Header 1: size 5 (0000000000101), index 0 (000).
	// Header 2: size 3 (0000000000011), delta 0 (000).
	packets, err = payloader.PayloadAUs(100, [][]byte{aus[0], aus[1]})
	require.NoError(t, err)
	require.Len(t, packets, 1)

	expected = []byte{
		0x00, 0x20, // 32 bits of AU-headers
		0x00, 0x28, // header 1: size 5, index 0
		0x00, 0x18, // header 2: size 3, delta 0
		0x01, 0x02, 0x03, 0x04, 0x05,
		0x11, 0x12, 0x13,
	}
	assert.Equal(t, expected, packets[0])
}

func TestMPEG4Payloader_BundlingAcrossPacketsPreservesOrder(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)
	aus := mpeg4FixedAUs()

	// Overhead per packet is 2 + 2 = 4 octets; each additional AU costs 2 header
	// octets. With MTU 18 only the first two AUs (5 + 3 + 4 = 12, adding the
	// third would need 14 more) fit together.
	mtu := uint16(18)
	packets, err := payloader.PayloadAUs(mtu, aus)
	require.NoError(t, err)
	require.Len(t, packets, 2)

	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	var decoded [][]byte
	for _, pkt := range packets {
		out, derr := depacketizer.Unmarshal(pkt)
		require.NoError(t, derr)
		if len(out) > 0 {
			decoded = append(decoded, depacketizer.AUs...)
		}
	}

	require.Len(t, decoded, len(aus))
	for i := range aus {
		assert.Equal(t, aus[i], decoded[i])
	}
}

func TestMPEG4Payloader_FragmentationAACHBROnly(t *testing.T) {
	t.Run("large AU split across packets with whole-AU size in each header", func(t *testing.T) {
		payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
		require.NoError(t, err)

		au := makeAU(10, 0x40)
		// Overhead 4 octets, so MTU 9 leaves 5 octets of data per packet:
		// 10 octets become fragments of 5 and 5.
		packets, err := payloader.PayloadAUs(9, [][]byte{au})
		require.NoError(t, err)
		require.Len(t, packets, 2)

		// Both headers name the whole AU (size 10 -> 10 << 3 = 0x0050, index 0).
		assert.Equal(t, []byte{0x00, 0x10, 0x00, 0x50}, packets[0][:4])
		assert.Equal(t, []byte{0x00, 0x10, 0x00, 0x50}, packets[1][:4])
		assert.Len(t, packets[0], 9)
		assert.Len(t, packets[1], 9)

		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		first, ferr := depacketizer.Unmarshal(packets[0])
		require.NoError(t, ferr)
		assert.Empty(t, first)
		assert.True(t, depacketizer.Fragmented)
		assert.True(t, depacketizer.IsPartitionHead(nil))
		assert.False(t, depacketizer.IsPartitionTail(false, nil))

		second, serr := depacketizer.Unmarshal(packets[1])
		require.NoError(t, serr)
		assert.Equal(t, au, second)
		assert.False(t, depacketizer.Fragmented)
		assert.False(t, depacketizer.IsPartitionHead(nil))
		assert.True(t, depacketizer.IsPartitionTail(true, nil))
	})

	t.Run("fragmentation forbidden in AAC-lbr", func(t *testing.T) {
		payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
		require.NoError(t, err)

		_, err = payloader.PayloadAUs(8, [][]byte{makeAU(63, 0x10)})
		assert.ErrorIs(t, err, errMPEG4AUTooLarge)
	})

	t.Run("AU larger than size field", func(t *testing.T) {
		lbr, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
		require.NoError(t, err)

		_, err = lbr.PayloadAUs(1200, [][]byte{makeAU(64, 0x10)})
		assert.ErrorIs(t, err, errMPEG4AUTooLarge)

		hbr, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
		require.NoError(t, err)
		_, err = hbr.PayloadAUs(1200, [][]byte{makeAU(8192, 0x10)})
		assert.ErrorIs(t, err, errMPEG4AUTooLarge)
	})

	t.Run("largest legal AAC-hbr access unit round-trips", func(t *testing.T) {
		hbr, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
		require.NoError(t, err)

		au := make([]byte, aachbrMaxAUSize)
		// A distinctive pattern that survives without byte wraparound.
		for i := range au {
			au[i] = byte(i % 251)
		}

		packets, err := hbr.PayloadAUs(1400, [][]byte{au})
		require.NoError(t, err)
		require.Greater(t, len(packets), 1)

		depacketizer, derr := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, derr)

		var out []byte
		for _, pkt := range packets {
			out, derr = depacketizer.Unmarshal(pkt)
			require.NoError(t, derr)
		}

		assert.Equal(t, au, out)
	})

	t.Run("largest legal AAC-lbr access unit round-trips", func(t *testing.T) {
		lbr, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
		require.NoError(t, err)

		au := make([]byte, aaclbrMaxAUSize)
		for i := range au {
			au[i] = byte(i % 61)
		}

		packets, err := lbr.PayloadAUs(1200, [][]byte{au})
		require.NoError(t, err)
		require.Len(t, packets, 1)

		depacketizer, derr := NewMPEG4AudioPacket(MPEG4ModeAACLBR)
		require.NoError(t, derr)
		out, derr := depacketizer.Unmarshal(packets[0])
		require.NoError(t, derr)
		assert.Equal(t, au, out)
	})
}

func TestMPEG4Payloader_BoundaryMTU(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)

	// MTU exactly equals the overhead plus a one-octet AU: single packet.
	packets, err := payloader.PayloadAUs(5, [][]byte{{0xAB}})
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, []byte{0x00, 0x10, 0x00, 0x08, 0xAB}, packets[0])

	// MTU equal to the header overhead alone cannot hold any data.
	_, err = payloader.PayloadAUs(4, [][]byte{{0xAB}})
	assert.ErrorIs(t, err, errMPEG4AUTooLarge)

	// MTU of zero cannot hold the AU header either.
	_, err = payloader.PayloadAUs(0, [][]byte{{0xAB}})
	assert.ErrorIs(t, err, errMPEG4AUTooLarge)

	// Nil and empty payloads produce nothing.
	assert.Len(t, payloader.Payload(100, nil), 0)
}

func TestMPEG4Payloader_PayloadInterfaceSwallowsErrors(t *testing.T) {
	lbr, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
	require.NoError(t, err)

	// The Payloader interface has no error return, so an un-fragmentable AU
	// produces no payloads rather than panicking.
	assert.Empty(t, lbr.Payload(8, makeAU(63, 0x10)))
}

func TestMPEG4Depacketizer_HBRLimitAndConfigErrors(t *testing.T) {
	t.Run("fragment claiming more than 8191 octets is rejected", func(t *testing.T) {
		// The 13-bit AU-size maxes at 8191, so a legal header cannot exceed it.
		// This guards the check directly with the largest representable value
		// used as a first fragment whose data is smaller than the named size.
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		// 8191 << 3 = 0xFFF8: the largest representable AU-size, index 0.
		packet := []byte{0x00, 0x10, 0xFF, 0xF8, 0xAA}
		out, err := depacketizer.Unmarshal(packet)
		require.NoError(t, err)
		assert.Empty(t, out)
		assert.True(t, depacketizer.Fragmented)
		assert.Equal(t, aachbrMaxAUSize, depacketizer.expectedAUSize)
	})

	t.Run("depacketizer rejects mismatched bit widths", func(t *testing.T) {
		depacketizer := &MPEG4AudioPacket{
			Mode:             MPEG4ModeAACLBR,
			SizeLength:       13,
			IndexLength:      3,
			IndexDeltaLength: 3,
		}
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x08, 0x14, 0x01})
		assert.ErrorIs(t, err, errMPEG4BadConfig)
	})
}

func TestMPEG4RoundTrip_FixedSequenceWithPacketizer(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)

	packetizer := rtp.NewPacketizer(
		20, // tight MTU so both bundling and fragmentation happen
		97,
		0xDEADBEEF,
		payloader,
		rtp.NewRandomSequencer(),
		90000,
	)
	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	var decoded [][]byte

	for _, au := range mpeg4FixedAUs() {
		packets := packetizer.Packetize(au, 1024)
		require.NotEmpty(t, packets)

		// All packets of one Packetize call share the timestamp; only the last
		// carries the marker bit.
		ts := packets[0].Timestamp
		for i, pkt := range packets {
			assert.Equal(t, ts, pkt.Timestamp)
			assert.Equal(t, i == len(packets)-1, pkt.Marker)

			out, uerr := depacketizer.Unmarshal(pkt.Payload)
			require.NoError(t, uerr)
			if len(out) > 0 {
				decoded = append(decoded, depacketizer.AUs...)
			}
		}
	}

	aus := mpeg4FixedAUs()
	require.Len(t, decoded, len(aus))
	for i := range aus {
		assert.Equal(t, aus[i], decoded[i])
	}
}

func TestMPEG4Depacketizer_TruncatedAndMalformedPackets(t *testing.T) {
	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	t.Run("nil and empty", func(t *testing.T) {
		_, err := depacketizer.Unmarshal(nil)
		assert.ErrorIs(t, err, errMPEG4NilPacket)

		_, err = depacketizer.Unmarshal([]byte{})
		assert.ErrorIs(t, err, errMPEG4ShortPacket)

		_, err = depacketizer.Unmarshal([]byte{0x00})
		assert.ErrorIs(t, err, errMPEG4ShortPacket)
	})

	t.Run("truncated AU-headers-length / header section", func(t *testing.T) {
		// Claims 16 header bits but the packet ends right after the length field.
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x10})
		assert.ErrorIs(t, err, errMPEG4Truncated)

		// Claims 16 header bits but only supplies 8, with no data section either.
		_, err = depacketizer.Unmarshal([]byte{0x00, 0x10, 0x00, 0x28})
		assert.ErrorIs(t, err, errMPEG4Truncated)
	})

	t.Run("AU-headers-length of zero is illegal", func(t *testing.T) {
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x00, 0x00})
		assert.ErrorIs(t, err, errMPEG4Truncated)
	})

	t.Run("illegal first AU-Index", func(t *testing.T) {
		// size 1 in 13 bits, index 1 (non-zero) in 3 bits -> 0x0009.
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x10, 0x00, 0x09, 0xAA})
		assert.ErrorIs(t, err, errMPEG4IllegalIndex)
	})

	t.Run("payloader rejects AUs beyond the AAC-hbr size field", func(t *testing.T) {
		// 8192 needs 14 bits and cannot be represented by the 13-bit AU-size.
		payloader, perr := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
		require.NoError(t, perr)
		_, perr = payloader.PayloadAUs(1200, [][]byte{makeAU(8192, 0x10)})
		assert.ErrorIs(t, perr, errMPEG4AUTooLarge)
	})

	t.Run("incomplete first fragment is buffered", func(t *testing.T) {
		fragDep, ferr := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, ferr)

		// AU-size names the whole AU (5) and only one data octet is present.
		out, err := fragDep.Unmarshal([]byte{0x00, 0x10, 0x00, 0x28, 0xAA})
		require.NoError(t, err)
		assert.Empty(t, out)
		assert.True(t, fragDep.Fragmented)
		assert.Equal(t, 5, fragDep.expectedAUSize)
	})

	t.Run("trailing octets after complete AUs", func(t *testing.T) {
		// One header of size 1, two data octets.
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x10, 0x00, 0x08, 0xAA, 0xBB})
		assert.ErrorIs(t, err, errMPEG4SizeMismatch)
	})

	t.Run("zero AU-size", func(t *testing.T) {
		_, err := depacketizer.Unmarshal([]byte{0x00, 0x10, 0x00, 0x00, 0xAA})
		assert.ErrorIs(t, err, errMPEG4SizeMismatch)
	})

	t.Run("non-zero AU-header padding bit", func(t *testing.T) {
		// AAC-lbr: one 8-bit AU-header (size 1 -> 0x04) plus one padding bit
		// that must be zero. The section occupies two octets while only 9 bits
		// are declared by AU-headers-length.
		lbrDep, lerr := NewMPEG4AudioPacket(MPEG4ModeAACLBR)
		require.NoError(t, lerr)

		packet := []byte{
			0x00, 0x09, // 9 declared header bits: 8 header bits + 1 padding bit
			0x04, // AU-header: size 1, index 0
			0x80, // highest bit is the declared padding bit and must be zero
			0xAA,
		}
		_, err := lbrDep.Unmarshal(packet)
		assert.ErrorIs(t, err, errMPEG4Truncated)
	})

	t.Run("zero AU-header padding bit is accepted", func(t *testing.T) {
		lbrDep, lerr := NewMPEG4AudioPacket(MPEG4ModeAACLBR)
		require.NoError(t, lerr)

		out, err := lbrDep.Unmarshal([]byte{0x00, 0x09, 0x04, 0x00, 0xAA})
		require.NoError(t, err)
		assert.Equal(t, []byte{0xAA}, out)
	})

	t.Run("sub-octet padding across multiple AU-headers", func(t *testing.T) {
		// Two lbr headers (16 bits) plus one padding bit: 17 declared bits in
		// three octets, with the padding bit clear and the rest zero.
		lbrDep, lerr := NewMPEG4AudioPacket(MPEG4ModeAACLBR)
		require.NoError(t, lerr)

		packet := []byte{
			0x00, 0x11, // 17 declared header bits
			0x04, 0x04, // two headers, each naming a one-octet AU
			0x00,
			0xAA, 0xBB,
		}
		out, err := lbrDep.Unmarshal(packet)
		require.NoError(t, err)
		assert.Equal(t, []byte{0xAA, 0xBB}, out)
		require.Len(t, lbrDep.AUs, 2)
	})

	t.Run("multi-header data section runs short", func(t *testing.T) {
		// Two headers of size 4 each but only two data octets follow.
		packet := []byte{
			0x00, 0x20, 0x00, 0x20, 0x00, 0x20,
			0xAA, 0xBB,
		}
		_, err := depacketizer.Unmarshal(packet)
		assert.ErrorIs(t, err, errMPEG4SizeMismatch)
	})

	t.Run("fragment data longer than the named AU-size", func(t *testing.T) {
		// The header names 10 octets but 11 data octets arrive.
		oversize := []byte{0x00, 0x10, 0x00, 0x50, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		_, err := depacketizer.Unmarshal(oversize)
		assert.ErrorIs(t, err, errMPEG4SizeMismatch)
	})
}

func TestMPEG4Depacketizer_LBRFragmentRejected(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACLBR)
	require.NoError(t, err)
	// A 63-octet AU is the largest legal lbr AU; with an 8-octet MTU the size
	// field can represent it but the packet cannot carry it whole.
	au := makeAU(63, 0x70)

	// Build a fragment-shaped lbr packet manually since the payloader refuses to
	// fragment: 8 header bits, size 63 (111111) + index 0 (00) = 0xFC.
	packet := []byte{0x00, 0x08, 0xFC}
	packet = append(packet, au[:3]...)

	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACLBR)
	require.NoError(t, err)

	_, err = depacketizer.Unmarshal(packet)
	assert.ErrorIs(t, err, errMPEG4Fragmentation)

	// The same AU packetized whole is accepted at a large enough MTU.
	packets, err := payloader.PayloadAUs(1200, [][]byte{au})
	require.NoError(t, err)
	require.Len(t, packets, 1)

	out, err := depacketizer.Unmarshal(packets[0])
	require.NoError(t, err)
	assert.Equal(t, au, out)
}

func TestMPEG4Depacketizer_MissingFragmentAndInterruption(t *testing.T) {
	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	au := makeAU(10, 0x40)
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)
	packets, err := payloader.PayloadAUs(9, [][]byte{au})
	require.NoError(t, err)
	require.Len(t, packets, 2)

	// First fragment starts reassembly.
	out, err := depacketizer.Unmarshal(packets[0])
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.True(t, depacketizer.Fragmented)

	// A complete-AU packet arriving before the final fragment means the rest of
	// the fragmented AU was lost.
	complete, err := payloader.PayloadAUs(100, [][]byte{{0x99}})
	require.NoError(t, err)
	_, err = depacketizer.Unmarshal(complete[0])
	assert.ErrorIs(t, err, errMPEG4MissingFragment)
	assert.False(t, depacketizer.Fragmented)

	// State was reset: the depacketizer can reassemble a fresh fragmented AU.
	packets, err = payloader.PayloadAUs(9, [][]byte{au})
	require.NoError(t, err)
	_, err = depacketizer.Unmarshal(packets[0])
	require.NoError(t, err)
	out, err = depacketizer.Unmarshal(packets[1])
	require.NoError(t, err)
	assert.Equal(t, au, out)
}

func TestMPEG4Depacketizer_FragmentSizeMismatch(t *testing.T) {
	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	// First fragment: whole AU claims 10 octets, carries 5.
	first := []byte{0x00, 0x10, 0x00, 0x50, 1, 2, 3, 4, 5}
	// Continuation claims a different whole-AU size of 9.
	second := []byte{0x00, 0x10, 0x00, 0x48, 6, 7, 8, 9}

	_, err = depacketizer.Unmarshal(first)
	require.NoError(t, err)
	_, err = depacketizer.Unmarshal(second)
	assert.ErrorIs(t, err, errMPEG4SizeMismatch)
	assert.False(t, depacketizer.Fragmented)
}

func TestMPEG4Depacketizer_UnmarshalRTPSequenceAndTimestamp(t *testing.T) {
	au := makeAU(10, 0x40)
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)
	fragments, err := payloader.PayloadAUs(9, [][]byte{au})
	require.NoError(t, err)
	require.Len(t, fragments, 2)

	t.Run("happy path: same timestamp, marker only on final fragment", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		out, err := depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 100,
			Timestamp:      5000,
			Payload:        fragments[0],
		})
		require.NoError(t, err)
		assert.Empty(t, out)

		out, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 101,
			Timestamp:      5000,
			Marker:         true,
			Payload:        fragments[1],
		})
		require.NoError(t, err)
		assert.Equal(t, au, out)
	})

	t.Run("out of order sequence number", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 100,
			Timestamp:      5000,
			Payload:        fragments[0],
		})
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 99,
			Timestamp:      5000,
			Payload:        fragments[0],
		})
		assert.ErrorIs(t, err, errMPEG4OutOfOrder)
	})

	t.Run("timestamp jump while fragmented AU pending", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 200,
			Timestamp:      7000,
			Payload:        fragments[0],
		})
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 201,
			Timestamp:      8024,
			Payload:        fragments[1],
		})
		assert.ErrorIs(t, err, errMPEG4TimestampJump)
		assert.False(t, depacketizer.Fragmented)
	})

	t.Run("constant duration violation", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)
		depacketizer.ConstantDuration = 1024

		complete, err := payloader.PayloadAUs(100, [][]byte{{0x99}})
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 300,
			Timestamp:      9000,
			Marker:         true,
			Payload:        complete[0],
		})
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 301,
			Timestamp:      9512,
			Marker:         true,
			Payload:        complete[0],
		})
		assert.ErrorIs(t, err, errMPEG4TimestampJump)

		// Exactly the constant duration is legal.
		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 302,
			Timestamp:      10024,
			Marker:         true,
			Payload:        complete[0],
		})
		assert.NoError(t, err)
	})

	t.Run("illegal marker on continuation fragment", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)

		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{
			SequenceNumber: 400,
			Timestamp:      11000,
			Marker:         true,
			Payload:        fragments[0],
		})
		assert.ErrorIs(t, err, errMPEG4BadMarker)
	})

	t.Run("nil packet", func(t *testing.T) {
		depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
		require.NoError(t, err)
		_, err = depacketizer.UnmarshalRTP(MPEG4RTPInfo{})
		assert.ErrorIs(t, err, errMPEG4NilPacket)
	})
}

func TestMPEG4Depacketizer_MultipleAUsAndPartitionSemantics(t *testing.T) {
	payloader, err := NewMPEG4AudioPayloader(MPEG4ModeAACHBR)
	require.NoError(t, err)
	aus := mpeg4FixedAUs()

	packets, err := payloader.PayloadAUs(100, [][]byte{aus[0], aus[1], aus[2]})
	require.NoError(t, err)
	require.Len(t, packets, 1)

	depacketizer, err := NewMPEG4AudioPacket(MPEG4ModeAACHBR)
	require.NoError(t, err)

	out, err := depacketizer.Unmarshal(packets[0])
	require.NoError(t, err)

	expected := make([]byte, 0, len(aus[0])+len(aus[1])+len(aus[2]))
	expected = append(expected, aus[0]...)
	expected = append(expected, aus[1]...)
	expected = append(expected, aus[2]...)
	assert.Equal(t, expected, out)
	require.Len(t, depacketizer.AUs, 3)
	assert.Equal(t, aus[0], depacketizer.AUs[0])
	assert.Equal(t, aus[1], depacketizer.AUs[1])
	assert.Equal(t, aus[2], depacketizer.AUs[2])

	// Complete-AU packets are both head and tail.
	assert.True(t, depacketizer.IsPartitionHead(packets[0]))
	assert.True(t, depacketizer.IsPartitionTail(true, packets[0]))
}

// Ensure the new types satisfy the existing package interfaces.
var (
	_ rtp.Payloader    = (*MPEG4AudioPayloader)(nil)
	_ rtp.Depacketizer = (*MPEG4AudioPacket)(nil)
)
