// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customJPEGLumaQuant is a deliberately non-standard zig-zag quantization
// table that no RFC 2435 static quality factor can reproduce.
//
//nolint:gochecknoglobals
var customJPEGLumaQuant = [64]byte{
	20, 14, 13, 20, 30, 50, 61, 73,
	15, 15, 17, 23, 31, 70, 72, 66,
	17, 16, 20, 29, 48, 68, 83, 67,
	17, 21, 27, 35, 61, 105, 96, 75,
	22, 27, 45, 68, 82, 131, 124, 93,
	29, 42, 66, 77, 97, 125, 136, 111,
	59, 77, 94, 105, 124, 145, 144, 122,
	87, 111, 115, 118, 135, 121, 124, 119,
}

// makeTestYCbCr builds a deterministic planar image. When subsample422 is
// true the chroma planes keep the full vertical resolution (4:2:2); otherwise
// they are halved in both directions (4:2:0).
func makeTestYCbCr(width, height int, subsample422 bool) *image.YCbCr {
	ratio := image.YCbCrSubsampleRatio420
	if subsample422 {
		ratio = image.YCbCrSubsampleRatio422
	}
	img := image.NewYCbCr(image.Rect(0, 0, width, height), ratio)
	for y := range height {
		for x := range width {
			yi := img.YOffset(x, y)
			img.Y[yi] = byte((x*7 + y*13) & 0xFF)
		}
	}

	chromaHeight := height / 2
	if subsample422 {
		chromaHeight = height
	}
	for y := 0; y < chromaHeight; y++ {
		for x := 0; x < width/2; x++ {
			ci := y*img.CStride + x
			img.Cb[ci] = byte((90 + x*5) & 0xFF)
			img.Cr[ci] = byte((200 - y*7) & 0xFF)
		}
	}

	return img
}

func TestJPEGTestEncoder_Decodable(t *testing.T) {
	// The test encoder must produce a stream that the standard library
	// decoder accepts, including with restart markers and custom tables.
	img := makeTestYCbCr(48, 32, false)
	_, chroma := makeJPEGStaticTables(75)

	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 2)
	require.NotEmpty(t, frame)
	assert.Equal(t, byte(0xD8), frame[1])

	decoded, err := jpeg.Decode(bytes.NewReader(frame))
	require.NoError(t, err)
	assert.Equal(t, 48, decoded.Bounds().Dx())
	assert.Equal(t, 32, decoded.Bounds().Dy())
}

func TestJPEGPayloader_Roundtrip(t *testing.T) {
	testCases := map[string]struct {
		sampling420 bool
		baseType    byte
		quality     int // <0 selects the non-standard custom luma table
		restart     int
		mtu         uint16
	}{
		"StaticTables_422_NoRestart": {
			sampling420: false, baseType: 0,
			quality: 50, restart: 0, mtu: 100,
		},
		"CustomTables_420_Restart": {
			sampling420: true, baseType: 1,
			quality: -1, restart: 2, mtu: 170,
		},
		"CustomTables_422_Restart": {
			sampling420: false, baseType: 0,
			quality: -1, restart: 1, mtu: 160,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var luma, chroma [64]byte
			dynamic := tc.quality < 0
			if dynamic {
				luma = customJPEGLumaQuant
				_, chroma = makeJPEGStaticTables(75)
			} else {
				luma, chroma = makeJPEGStaticTables(tc.quality)
			}

			img := makeTestYCbCr(48, 32, !tc.sampling420)
			frame := encodeJPEGTestFrame(img, tc.sampling420, luma, chroma, tc.restart)

			payloader := &JPEGPayloader{}
			packets := payloader.Payload(tc.mtu, frame)
			require.NotEmpty(t, packets)
			require.GreaterOrEqual(t, len(packets), 2, "fixture must force fragmentation")

			// Every packet must respect the MTU and share type/Q/dimensions.
			for i, pkt := range packets {
				assert.LessOrEqual(t, len(pkt), int(tc.mtu))
				assert.Equal(t, packets[0][4], pkt[4], "type must be stable")
				assert.Equal(t, packets[0][5], pkt[5], "Q must be stable")
				assert.Equal(t, packets[0][6], pkt[6], "width must be stable")
				assert.Equal(t, packets[0][7], pkt[7], "height must be stable")

				offset := uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3])
				if i == 0 {
					assert.Zero(t, offset)
					assert.True(t, (&JPEGPacket{}).IsPartitionHead(pkt))
				} else {
					assert.NotZero(t, offset)
				}
			}

			assert.Equal(t, tc.baseType, packets[0][4]&^jpegTypeRestart)
			if tc.restart > 0 {
				assert.Equal(t, byte(jpegTypeRestart), packets[0][4]&jpegTypeRestart)
				interval := binary.BigEndian.Uint16(packets[0][8:10])
				assert.Equal(t, uint16(tc.restart), interval) //nolint:gosec // small DRI value
			} else {
				assert.Zero(t, packets[0][4]&jpegTypeRestart)
			}
			if dynamic {
				assert.Equal(t, byte(jpegDynamicQ), packets[0][5])
			} else {
				assert.Equal(t, byte(tc.quality), packets[0][5]) //nolint:gosec // quality in [1,99]
			}

			// Reassemble and decode through the depacketizer.
			depacketizer := &JPEGPacket{}
			for i, pkt := range packets {
				out, err := depacketizer.Unmarshal(pkt)
				require.NoError(t, err)
				assert.Empty(t, out, "incomplete frames must not emit media yet")
				isFinal := i == len(packets)-1
				assert.Equal(t, isFinal,
					depacketizer.IsDetectedFinalPacketInSequence(isFinal))
				if isFinal {
					depacketizer.MarkFrameEnd()
				}
			}

			assembled, err := depacketizer.Flush()
			require.NoError(t, err)
			assert.True(t, bytes.HasPrefix(assembled, []byte{0xFF, 0xD8}))
			assert.True(t, bytes.HasSuffix(assembled, []byte{0xFF, 0xD9}))

			decoded, err := jpeg.Decode(bytes.NewReader(assembled))
			require.NoError(t, err)
			assert.Equal(t, 48, decoded.Bounds().Dx())
			assert.Equal(t, 32, decoded.Bounds().Dy())

			// Round-tripped pixels must match the source (lossless metadata
			// path: same quant tables, same Huffman tables).
			roundtrip, err := jpeg.Decode(bytes.NewReader(frame))
			require.NoError(t, err)
			assert.True(t, imagesEqual(decoded, roundtrip))
		})
	}
}

func imagesEqual(a, b image.Image) bool {
	if a.Bounds() != b.Bounds() {
		return false
	}
	for y := a.Bounds().Min.Y; y < a.Bounds().Max.Y; y++ {
		for x := a.Bounds().Min.X; x < a.Bounds().Max.X; x++ {
			ar, ag, ab, _ := a.At(x, y).RGBA()
			br, bg, bb, _ := b.At(x, y).RGBA()
			if ar != br || ag != bg || ab != bb {
				return false
			}
		}
	}

	return true
}

func TestJPEGPayloader_SinglePacket(t *testing.T) {
	img := makeTestYCbCr(16, 16, true)
	luma, chroma := makeJPEGStaticTables(80)
	frame := encodeJPEGTestFrame(img, false, luma, chroma, 0)

	packets := (&JPEGPayloader{}).Payload(1500, frame)
	require.Len(t, packets, 1)
	assert.True(t, (&JPEGPacket{}).IsPartitionHead(packets[0]))

	depacketizer := &JPEGPacket{}
	out, err := depacketizer.Unmarshal(packets[0])
	require.NoError(t, err)
	assert.Empty(t, out)
	depacketizer.MarkFrameEnd()

	assembled, err := depacketizer.Flush()
	require.NoError(t, err)
	_, err = jpeg.Decode(bytes.NewReader(assembled))
	assert.NoError(t, err)
}

func TestJPEGPayloader_RejectsUnsupported(t *testing.T) {
	img := makeTestYCbCr(16, 16, false)
	luma, chroma := makeJPEGStaticTables(75)
	frame := encodeJPEGTestFrame(img, true, luma, chroma, 0)

	testCases := map[string]struct {
		mutate  func([]byte) []byte
		wantErr error
	}{
		"Nil": {
			mutate:  func([]byte) []byte { return nil },
			wantErr: errJPEGMissingSOI,
		},
		"MissingSOI": {
			mutate:  func(b []byte) []byte { return b[2:] },
			wantErr: errJPEGMissingSOI,
		},
		"ProgressiveSOF": {
			mutate: func(b []byte) []byte {
				out := bytes.Clone(b)
				idx := markerIndex(out, jpegSOF0)
				out[idx+1] = 0xC2 // SOF2: progressive

				return out
			},
			wantErr: errJPEGUnsupportedMode,
		},
		"FourByFourSampling": {
			mutate: func(b []byte) []byte {
				out := bytes.Clone(b)
				idx := markerIndex(out, jpegSOF0)
				// SOF payload starts after marker+length; Y sampling byte is
				// offset 7 within the segment.
				out[idx+4+7] = 0x44

				return out
			},
			wantErr: errJPEGUnsupportedSampling,
		},
		"Truncated": {
			mutate: func(b []byte) []byte {
				// Cut inside the DQT segment so its declared length overruns.
				dqt := markerIndex(b, jpegDQT)

				return b[:dqt+10]
			},
			wantErr: errJPEGTruncatedSegment,
		},
		"RSTWithoutDRI": {
			mutate: func(b []byte) []byte {
				// Inject an RST marker directly into the scan data; no DRI is
				// present, so restart markers are illegal here.
				out := bytes.Clone(b)
				sos := markerIndex(out, jpegSOS)
				scanStart := sos + 2 + 2 + 10
				out = append(out[:scanStart], append(
					[]byte{0xFF, 0xD0}, out[scanStart:]...)...)

				return out
			},
			wantErr: errJPEGRestartMarkerOutside,
		},
		"MissingQuantTables": {
			mutate: func(b []byte) []byte {
				// Remove the DQT segment entirely.
				dqt := markerIndex(b, jpegDQT)
				length := int(binary.BigEndian.Uint16(b[dqt+2:]))

				return append(bytes.Clone(b[:dqt]), b[dqt+2+length:]...)
			},
			wantErr: errJPEGMissingQuantization,
		},
		"SixteenBitDQT": {
			mutate: func(b []byte) []byte {
				// Request 16-bit precision in the first DQT table.
				out := bytes.Clone(b)
				dqt := markerIndex(out, jpegDQT)
				out[dqt+4] = 0x10

				return out
			},
			wantErr: errJPEGUnsupportedPrecision,
		},
		"CorruptedHuffmanTable": {
			mutate: func(b []byte) []byte {
				// Flip a symbol inside the luma DC Huffman table so it no
				// longer matches Annex K.3.
				out := bytes.Clone(b)
				dht := markerIndex(out, jpegDHT)
				out[dht+4+17] ^= 0x01

				return out
			},
			wantErr: errJPEGNonStandardHuffman,
		},
		"BadScanHeader": {
			mutate: func(b []byte) []byte {
				// Rewrite the SOS component count to a single component.
				out := bytes.Clone(b)
				sos := markerIndex(out, jpegSOS)
				out[sos+4] = 1

				return out
			},
			wantErr: errJPEGInvalidScan,
		},
		"BadSofDimensions": {
			mutate: func(b []byte) []byte {
				// A width of 12 pixels is not a multiple of 8.
				out := bytes.Clone(b)
				sof := markerIndex(out, jpegSOF0)
				out[sof+8] = 0 // width high byte
				out[sof+9] = 12

				return out
			},
			wantErr: errJPEGInvalidDimension,
		},
		"MarkerInsideScan": {
			mutate: func(b []byte) []byte {
				// Inject a COM marker into the entropy-coded scan.
				out := bytes.Clone(b)
				sos := markerIndex(out, jpegSOS)
				scanStart := sos + 2 + 2 + 10
				out = append(out[:scanStart], append(
					[]byte{0xFF, 0xFE}, out[scanStart:]...)...)

				return out
			},
			wantErr: errJPEGMarkerInScan,
		},
		"UnknownQuantTableID": {
			mutate: func(b []byte) []byte {
				// Address the second DQT table at identifier 7 instead of 1.
				out := bytes.Clone(b)
				dqt := markerIndex(out, jpegDQT)
				out[dqt+4+65] = 7

				return out
			},
			wantErr: errJPEGQuantTable,
		},
		"UnknownHuffmanTableID": {
			mutate: func(b []byte) []byte {
				// Address an undefined Huffman table (class 0, table 3).
				out := bytes.Clone(b)
				dht := markerIndex(out, jpegDHT)
				out[dht+4] = 0x03

				return out
			},
			wantErr: errJPEGNonStandardHuffman,
		},
		"TruncatedEntropyData": {
			mutate: func(b []byte) []byte {
				// End the file on a bare 0xFF inside the scan.
				out := bytes.Clone(b)
				sos := markerIndex(out, jpegSOS)
				scanStart := sos + 2 + 2 + 10

				return append(out[:scanStart], 0xFF)
			},
			wantErr: errJPEGTruncatedSegment,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			payload := tc.mutate(frame)
			_, err := parseJPEGFrame(payload)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, (&JPEGPayloader{}).Payload(1500, payload))
		})
	}
}

func TestJPEGPayloader_MTUBoundaries(t *testing.T) {
	img := makeTestYCbCr(16, 16, true)
	luma, chroma := makeJPEGStaticTables(80)
	frame := encodeJPEGTestFrame(img, false, luma, chroma, 0)

	t.Run("ZeroMTU", func(t *testing.T) {
		assert.Empty(t, (&JPEGPayloader{}).Payload(0, frame))
	})

	t.Run("HeaderSizedMTU", func(t *testing.T) {
		// Exactly the main header leaves no room for scan data.
		assert.Empty(t, (&JPEGPayloader{}).Payload(jpegMainHeaderSize, frame))
	})

	t.Run("DynamicTablesNeedLargerMTU", func(t *testing.T) {
		custom := encodeJPEGTestFrame(img, false, customJPEGLumaQuant, chroma, 0)
		// The in-band tables alone exceed a 100-byte MTU.
		assert.Empty(t, (&JPEGPayloader{}).Payload(100, custom))

		packets := (&JPEGPayloader{}).Payload(200, custom)
		require.NotEmpty(t, packets)
		for _, pkt := range packets {
			assert.LessOrEqual(t, len(pkt), 200)
		}
	})
}

func TestJPEGPacket_DimensionBounds(t *testing.T) {
	// 255 8-pixel blocks = 2040 pixels, the largest expressible dimension.
	maxSize := []byte{0, 0, 0, 0, 0, 50, 255, 4, 0xAA}
	depacketizer := &JPEGPacket{}
	_, err := depacketizer.Unmarshal(maxSize)
	require.NoError(t, err)
	assert.Equal(t, uint16(2040), depacketizer.Width)
	assert.Equal(t, uint16(32), depacketizer.Height)

	// Zero height is outside the 8-pixel-block encoding.
	badHeight := []byte{0, 0, 0, 0, 0, 50, 4, 0, 0xAA}
	_, err = (&JPEGPacket{}).Unmarshal(badHeight)
	assert.ErrorIs(t, err, errJPEGInvalidDimension)
}

func TestJPEGPacket_ZeroLengthQuantHeader(t *testing.T) {
	// Q=255 with a quantization header declaring zero table bytes.
	payload := []byte{
		0, 0, 0, 0, // type-specific + offset
		0, 255, // type 0, dynamic Q
		2, 2, // 16x16
		0, 0, 0, 0, // MBZ, precision, length = 0
		0xAA, // scan byte
	}
	_, err := (&JPEGPacket{}).Unmarshal(payload)
	assert.ErrorIs(t, err, errJPEGQuantTable)
}

func TestJPEGPacket_BadQuantTableContent(t *testing.T) {
	// A declared length that does not hold exactly two 8-bit tables.
	payload := []byte{
		0, 0, 0, 0,
		0, 200, // type 0, static dynamic Q
		2, 2,
		0, 0, 0, 10, // MBZ, 8-bit precision, length 10 (too short)
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	}
	_, err := (&JPEGPacket{}).Unmarshal(payload)
	assert.ErrorIs(t, err, errJPEGQuantTable)
}

func TestJPEGPacket_MBZMustBeZero(t *testing.T) {
	payload := []byte{
		0, 0, 0, 0,
		0, 200,
		2, 2,
		7, 0, 0, 0, // MBZ set to a non-zero value, length 0
	}
	_, err := (&JPEGPacket{}).Unmarshal(payload)
	assert.ErrorIs(t, err, errJPEGQuantTable)
}

func markerIndex(frame []byte, marker byte) int {
	for i := 0; i < len(frame)-1; i++ {
		if frame[i] == 0xFF && frame[i+1] == marker {
			return i
		}
	}

	return -1
}

func TestJPEGPacket_UnmarshalErrors(t *testing.T) {
	img := makeTestYCbCr(32, 16, true)
	luma, chroma := makeJPEGStaticTables(60)
	frame := encodeJPEGTestFrame(img, false, luma, chroma, 0)
	packets := (&JPEGPayloader{}).Payload(64, frame)
	require.GreaterOrEqual(t, len(packets), 2)

	t.Run("ShortPacket", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Unmarshal(packets[0][:7])
		assert.ErrorIs(t, err, errJPEGShortPacket)
	})

	t.Run("UnsupportedType", func(t *testing.T) {
		d := &JPEGPacket{}
		pkt := bytes.Clone(packets[0])
		pkt[4] = 2
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGInvalidType)

		pkt = bytes.Clone(packets[0])
		pkt[4] = 128
		_, err = d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGInvalidType)
	})

	t.Run("ZeroDimension", func(t *testing.T) {
		d := &JPEGPacket{}
		pkt := bytes.Clone(packets[0])
		pkt[6] = 0
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGInvalidDimension)
	})

	t.Run("ReservedQ", func(t *testing.T) {
		d := &JPEGPacket{}
		pkt := bytes.Clone(packets[0])
		pkt[5] = 0
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGInvalidQ)

		pkt = bytes.Clone(packets[0])
		pkt[5] = 100
		_, err = d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGInvalidQ)
	})

	t.Run("QuantLengthExceedsPayload", func(t *testing.T) {
		dyn := dynamicJPEGPackets(t)
		d := &JPEGPacket{}
		pkt := bytes.Clone(dyn[0])
		// Length field sits at main-header+2..+4.
		binary.BigEndian.PutUint16(pkt[10:12], 60000)
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGQuantLength)
	})

	t.Run("DynamicQWithZeroLength", func(t *testing.T) {
		dyn := dynamicJPEGPackets(t)
		d := &JPEGPacket{}
		pkt := bytes.Clone(dyn[0])
		binary.BigEndian.PutUint16(pkt[10:12], 0)
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGQuantTable)
	})

	t.Run("16BitQuantPrecision", func(t *testing.T) {
		dyn := dynamicJPEGPackets(t)
		d := &JPEGPacket{}
		pkt := bytes.Clone(dyn[0])
		pkt[9] = 0x03 // both tables marked 16-bit
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGUnsupportedPrecision)
	})

	t.Run("RestartIntervalZero", func(t *testing.T) {
		restart := restartJPEGPackets(t)
		d := &JPEGPacket{}
		pkt := bytes.Clone(restart[0])
		binary.BigEndian.PutUint16(pkt[8:10], 0)
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGRestartIntervalZero)
	})

	t.Run("RestartHeaderMissing", func(t *testing.T) {
		restart := restartJPEGPackets(t)
		d := &JPEGPacket{}
		// Keep only the 8-byte main header; the restart header is absent.
		pkt := bytes.Clone(restart[0])[:jpegMainHeaderSize]
		_, err := d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGRestartMissing)
	})

	t.Run("HeaderMismatch", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Unmarshal(packets[0])
		require.NoError(t, err)
		pkt := bytes.Clone(packets[1])
		pkt[4] ^= 1 // flip base type
		_, err = d.Unmarshal(pkt)
		assert.ErrorIs(t, err, errJPEGHeaderMismatch)
	})

	t.Run("MissingFirstFragment", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Unmarshal(packets[1])
		assert.ErrorIs(t, err, errJPEGIncompleteFrame)
	})
}

func dynamicJPEGPackets(t *testing.T) [][]byte {
	t.Helper()
	img := makeTestYCbCr(32, 16, false)
	_, chroma := makeJPEGStaticTables(75)
	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 0)
	// MTU must leave room for the 132-byte in-band quantization header.
	packets := (&JPEGPayloader{}).Payload(200, frame)
	require.NotEmpty(t, packets)
	require.Equal(t, byte(jpegDynamicQ), packets[0][5])

	return packets
}

func restartJPEGPackets(t *testing.T) [][]byte {
	t.Helper()
	img := makeTestYCbCr(48, 32, false)
	_, chroma := makeJPEGStaticTables(75)
	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 2)
	// MTU must leave room for the 132-byte in-band quantization header.
	packets := (&JPEGPayloader{}).Payload(200, frame)
	require.NotEmpty(t, packets)
	require.Equal(t, byte(jpegTypeRestart), packets[0][4]&jpegTypeRestart)

	return packets
}

func TestJPEGPacket_Reassembly(t *testing.T) {
	img := makeTestYCbCr(48, 32, false)
	_, chroma := makeJPEGStaticTables(75)
	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 2)
	packets := (&JPEGPayloader{}).Payload(200, frame)
	require.GreaterOrEqual(t, len(packets), 3)

	t.Run("InOrder", func(t *testing.T) {
		d := &JPEGPacket{}
		for _, pkt := range packets {
			_, err := d.Unmarshal(pkt)
			require.NoError(t, err)
		}
		d.MarkFrameEnd()
		assembled, err := d.Flush()
		require.NoError(t, err)
		_, err = jpeg.Decode(bytes.NewReader(assembled))
		assert.NoError(t, err)
	})

	t.Run("Reordered", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Unmarshal(packets[0])
		require.NoError(t, err)
		_, err = d.Unmarshal(packets[2]) // gap, but offset known
		require.NoError(t, err)
		_, err = d.Unmarshal(packets[1]) // fills the gap
		require.NoError(t, err)
		d.MarkFrameEnd()

		assembled, err := d.Flush()
		require.NoError(t, err)
		_, err = jpeg.Decode(bytes.NewReader(assembled))
		assert.NoError(t, err)
	})

	t.Run("MissingFragment", func(t *testing.T) {
		depacketizer := &JPEGPacket{}
		for i, pkt := range packets {
			if i == 1 {
				continue
			}
			_, err := depacketizer.Unmarshal(pkt)
			require.NoError(t, err)
		}
		// The marked final packet was received, but a middle fragment is gone.
		depacketizer.MarkFrameEnd()
		_, err := depacketizer.Flush()
		assert.ErrorIs(t, err, errJPEGIncompleteFrame)

		// State resets after Flush.
		_, err = depacketizer.Flush()
		assert.ErrorIs(t, err, errJPEGIncompleteFrame)
	})

	t.Run("DuplicateFragment", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Unmarshal(packets[0])
		require.NoError(t, err)
		_, err = d.Unmarshal(packets[1])
		require.NoError(t, err)
		_, err = d.Unmarshal(packets[1])
		assert.ErrorIs(t, err, errJPEGDuplicateFragment)
	})

	t.Run("OverlappingFragment", func(t *testing.T) {
		depacketizer := &JPEGPacket{}
		_, err := depacketizer.Unmarshal(packets[0])
		require.NoError(t, err)
		_, err = depacketizer.Unmarshal(packets[1])
		require.NoError(t, err)

		// Forge a fragment starting inside the second packet's range.
		overlap := bytes.Clone(packets[1])
		offset := uint32(packets[1][1])<<16 | uint32(packets[1][2])<<8 |
			uint32(packets[1][3])
		offset++
		overlap[1], overlap[2], overlap[3] = byte(offset>>16), byte(offset>>8), byte(offset) //nolint:gosec // 24-bit RTP offset
		_, err = depacketizer.Unmarshal(overlap)
		assert.ErrorIs(t, err, errJPEGOverlappingFragment)
	})

	t.Run("EmptyFlush", func(t *testing.T) {
		d := &JPEGPacket{}
		_, err := d.Flush()
		assert.ErrorIs(t, err, errJPEGIncompleteFrame)
	})

	t.Run("ContiguousPrefixWithoutMarker", func(t *testing.T) {
		// Feed every fragment except the last but never signal the marker.
		// A contiguous prefix must not be confused with a complete frame.
		depacketizer := &JPEGPacket{}
		for _, pkt := range packets[:len(packets)-1] {
			_, err := depacketizer.Unmarshal(pkt)
			require.NoError(t, err)
		}
		_, err := depacketizer.Flush()
		assert.ErrorIs(t, err, errJPEGIncompleteFrame)
	})
}

func TestJPEGPacket_IsPartitionHead(t *testing.T) {
	assert.False(t, (&JPEGPacket{}).IsPartitionHead(nil))
	assert.False(t, (&JPEGPacket{}).IsPartitionHead([]byte{0, 0, 0, 1, 0, 50, 4, 4}))
	assert.True(t, (&JPEGPacket{}).IsPartitionHead([]byte{0, 0, 0, 0, 0, 50, 4, 4}))
}

func TestJPEGStaticTables(t *testing.T) {
	// RFC 2435 Appendix A boundary behavior. At Q=1 the scale factor is
	// S=5000, so every coefficient saturates to the 255 ceiling.
	q1, _ := makeJPEGStaticTables(1)
	assert.Equal(t, byte(255), q1[0])
	assert.Equal(t, byte(255), q1[63])

	// At Q=99, S=2; the smallest coefficient floors to 1.
	q99, _ := makeJPEGStaticTables(99)
	assert.Equal(t, byte(1), q99[0])

	// Quality factors outside the defined range are clamped like the C code.
	q0, q0c := makeJPEGStaticTables(0)
	q1b, q1c := makeJPEGStaticTables(1)
	assert.Equal(t, q1b, q0)
	assert.Equal(t, q1c, q0c)

	// A static-table frame round-trips through the Q field without an
	// in-band quantization header.
	img := makeTestYCbCr(16, 16, true)
	luma, chroma := makeJPEGStaticTables(55)
	frame := encodeJPEGTestFrame(img, false, luma, chroma, 0)
	packets := (&JPEGPayloader{}).Payload(1500, frame)
	require.Len(t, packets, 1)
	assert.Equal(t, byte(55), packets[0][5])
	assert.Len(t, packets[0], jpegMainHeaderSize+scanLen(frame))

	d := &JPEGPacket{}
	_, err := d.Unmarshal(packets[0])
	require.NoError(t, err)
	assert.Equal(t, luma, d.LumaQuant)
	assert.Equal(t, chroma, d.ChromaQuant)
}

func scanLen(frame []byte) int {
	idx := markerIndex(frame, jpegSOS)
	// Skip marker (2), segment length (2), SOS segment body (10).
	return len(frame) - (idx + 2 + 2 + 10) - 2 // minus EOI
}

func TestJPEGRestartHeaderSemantics(t *testing.T) {
	img := makeTestYCbCr(48, 32, false)
	_, chroma := makeJPEGStaticTables(75)
	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 1)

	t.Run("AlignedChunks", func(t *testing.T) {
		// A generous MTU lets the payloader align every packet to a restart
		// marker, so the chunk F/L bits and restart counts become meaningful.
		packets := (&JPEGPayloader{}).Payload(200, frame)
		require.GreaterOrEqual(t, len(packets), 2)

		parsed, err := parseJPEGFrame(frame)
		require.NoError(t, err)
		require.NotEmpty(t, parsed.rstOffsets)

		for i, pkt := range packets {
			flagsCount := binary.BigEndian.Uint16(pkt[10:12])
			assert.True(t, flagsCount&0x8000 != 0, "packet %d must set F", i)
			assert.True(t, flagsCount&0x4000 != 0, "packet %d must set L", i)
			count := flagsCount & jpegRestartCountMask
			assert.NotEqual(t, jpegRestartCountMask, count,
				"aligned packets must not use the 0x3FFF fallback")

			offset := uint32(pkt[1])<<16 | uint32(pkt[2])<<8 | uint32(pkt[3])
			if offset == 0 {
				assert.Zero(t, count)
			} else {
				// Every non-head packet starts just past an RST marker and
				// therefore carries a positive, increasing restart count.
				assert.NotZero(t, count)
			}
		}

		// Reassembly through the aligned chunks still yields a decodable JPEG.
		d := &JPEGPacket{}
		for _, pkt := range packets {
			_, err = d.Unmarshal(pkt)
			require.NoError(t, err)
		}
		d.MarkFrameEnd()
		assembled, err := d.Flush()
		require.NoError(t, err)
		_, err = jpeg.Decode(bytes.NewReader(assembled))
		assert.NoError(t, err)
	})

	t.Run("FullReassemblyFallback", func(t *testing.T) {
		// Use a long restart interval (every 4 MCUs) so that an interval is
		// larger than the MTU. Packet boundaries then cannot align to markers
		// and every packet must carry the RFC fallback F=L=1, count=0x3FFF.
		bigInterval := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 4)
		packets := (&JPEGPayloader{}).Payload(150, bigInterval)
		require.GreaterOrEqual(t, len(packets), 2)

		for i, pkt := range packets {
			flagsCount := binary.BigEndian.Uint16(pkt[10:12])
			assert.True(t, flagsCount&0x8000 != 0, "packet %d must set F", i)
			assert.True(t, flagsCount&0x4000 != 0, "packet %d must set L", i)
			assert.Equal(t, uint16(jpegRestartCountMask),
				flagsCount&jpegRestartCountMask,
				"unaligned packets must carry the 0x3FFF fallback count")
		}

		d := &JPEGPacket{}
		for _, pkt := range packets {
			_, err := d.Unmarshal(pkt)
			require.NoError(t, err)
		}
		d.MarkFrameEnd()
		assembled, err := d.Flush()
		require.NoError(t, err)
		_, err = jpeg.Decode(bytes.NewReader(assembled))
		assert.NoError(t, err)
	})
}

func TestJPEGOffsetTooLarge(t *testing.T) {
	d := &JPEGPacket{}
	head := []byte{0, 0, 0, 0, 0, 50, 2, 2, 0xAA}
	_, err := d.Unmarshal(head)
	require.NoError(t, err)

	// A two-byte fragment at offset 2^24-2 ends exactly at 2^24, which is
	// legal; one more byte crosses the 24-bit frame space and must be rejected.
	edge := []byte{0, 0xFF, 0xFF, 0xFE, 0, 50, 2, 2, 0xBB, 0xCC}
	_, err = d.Unmarshal(edge)
	require.NoError(t, err)

	over := []byte{0, 0xFF, 0xFF, 0xFE, 0, 50, 2, 2, 0xBB, 0xCC, 0xDD}
	_, err = d.Unmarshal(over)
	assert.ErrorIs(t, err, errJPEGOffsetTooLarge)
}

// Keep the color package import meaningful for future pixel-level assertions
// while documenting the YCbCr color space of the fixture.
var _ color.Model = color.YCbCrModel
