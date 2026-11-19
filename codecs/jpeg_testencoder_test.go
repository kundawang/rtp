// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"bytes"
	"encoding/binary"
	"image"
	"math"
)

// This file contains a minimal baseline JPEG encoder used only by the RFC
// 2435 tests. Unlike image/jpeg.Encode it supports restart markers and
// arbitrary quantization tables, which are required to exercise the RTP/JPEG
// payload format. The generated stream uses the standard Annex K.3 Huffman
// tables and is decodable by any conformant baseline decoder.

type jpegTestEncoder struct {
	buf          bytes.Buffer
	bitBuffer    uint32
	bitCount     uint32
	restartEvery int
	mcus         int
	restartCount int
	prevDC       [3]int
	huffLUT      [4]jpegTestLUT
}

type jpegTestLUT struct {
	code  [256]uint32
	count [256]uint8
}

func (e *jpegTestEncoder) emitByte(b byte) {
	e.buf.WriteByte(b)
	// Entropy-coded 0xFF bytes require a stuffed 0x00.
	if b == 0xFF {
		e.buf.WriteByte(0x00)
	}
}

func (e *jpegTestEncoder) emitBits(value uint32, nBits uint32) {
	e.bitBuffer = (e.bitBuffer << nBits) | (value & ((1 << nBits) - 1))
	e.bitCount += nBits
	for e.bitCount >= 8 {
		e.bitCount -= 8
		e.emitByte(byte(e.bitBuffer >> e.bitCount)) //nolint:gosec // shifted down to a byte
	}
}

func (e *jpegTestEncoder) flushBits() {
	if e.bitCount > 0 {
		// Pad the final byte with 1-bits.
		e.emitBits(^uint32(0)&((1<<(8-e.bitCount))-1), 8-e.bitCount)
	}
	e.bitBuffer = 0
	e.bitCount = 0
}

func (e *jpegTestEncoder) emitMarker(marker byte) {
	e.buf.WriteByte(0xFF)
	e.buf.WriteByte(marker)
}

func (e *jpegTestEncoder) emitSegment(marker byte, payload []byte) {
	e.emitMarker(marker)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)+2)) //nolint:gosec
	e.buf.Write(length[:])
	e.buf.Write(payload)
}

func (e *jpegTestEncoder) buildLUT(specLengths [16]byte, specSymbols []byte) jpegTestLUT {
	lut := jpegTestLUT{}
	var code uint32
	var k int
	for length := 1; length <= 16; length++ {
		for range specLengths[length-1] {
			symbol := specSymbols[k]
			lut.code[symbol] = code
			lut.count[symbol] = uint8(length) //nolint:gosec
			code++
			k++
		}
		code <<= 1
	}

	return lut
}

func (e *jpegTestEncoder) initHuffman() {
	e.huffLUT[0] = e.buildLUT(jpegLumaDCCodeLengths, jpegLumaDCSymbols[:])
	e.huffLUT[1] = e.buildLUT(jpegLumaACCodeLengths, jpegLumaACSymbols[:])
	e.huffLUT[2] = e.buildLUT(jpegChromaDCCodeLengths, jpegChromaDCSymbols[:])
	e.huffLUT[3] = e.buildLUT(jpegChromaACCodeLengths, jpegChromaACSymbols[:])
}

func jpegTestBits(value int) (uint32, uint32) {
	if value == 0 {
		return 0, 0
	}
	abs := value
	if abs < 0 {
		abs = -abs
	}
	var nBits uint32
	for v := abs; v != 0; v >>= 1 {
		nBits++
	}
	// Encode negative values as ones' complement.
	if value < 0 {
		value += (1 << nBits) - 1
	}

	return uint32(value), nBits //nolint:gosec // JPEG coefficients fit in 11 bits
}

func (e *jpegTestEncoder) encodeBlock(block [64]int32, quant [64]byte, huffIndex int, comp int) {
	// DC coefficient: difference coded.
	dc := int(block[0]) / int(quant[0])
	diff := dc - e.prevDC[comp]
	e.prevDC[comp] = dc
	bits, nBits := jpegTestBits(diff)
	e.emitBits(e.huffLUT[huffIndex].code[nBits], uint32(e.huffLUT[huffIndex].count[nBits]))
	e.emitBits(bits, nBits)

	// AC coefficients in zig-zag order.
	run := 0
	for k := 1; k < 64; k++ {
		coeff := int(block[jpegTestZigZag[k]]) / int(quant[k])
		if coeff == 0 {
			run++

			continue
		}
		for run > 15 {
			// ZRL.
			e.emitBits(e.huffLUT[huffIndex+1].code[0xF0],
				uint32(e.huffLUT[huffIndex+1].count[0xF0]))
			run -= 16
		}
		bits, nBits = jpegTestBits(coeff)
		rs := byte(run<<4) | byte(nBits) //nolint:gosec
		e.emitBits(e.huffLUT[huffIndex+1].code[rs],
			uint32(e.huffLUT[huffIndex+1].count[rs]))
		e.emitBits(bits, nBits)
		run = 0
	}
	if run > 0 {
		// EOB.
		e.emitBits(e.huffLUT[huffIndex+1].code[0x00],
			uint32(e.huffLUT[huffIndex+1].count[0x00]))
	}
}

func (e *jpegTestEncoder) emitRestart() {
	e.flushBits()
	e.emitMarker(0xD0 + byte(e.restartCount%8)) //nolint:gosec
	e.restartCount++
}

// encodeJPEGTestFrame writes a baseline JPEG of img. sampling420 selects
// type 1 (4:2:0); otherwise type 0 (4:2:2) is produced. lumaQuant and
// chromaQuant are zig-zag-ordered 8-bit quantization tables. restartEvery is
// the DRI interval in MCUs (zero disables restart markers).
func encodeJPEGTestFrame(
	img *image.YCbCr,
	sampling420 bool,
	lumaQuant, chromaQuant [64]byte,
	restartEvery int,
) []byte {
	enc := &jpegTestEncoder{restartEvery: restartEvery}
	enc.initHuffman()

	width := img.Bounds().Dx()
	height := img.Bounds().Dy()

	// SOI.
	enc.emitMarker(jpegSOI)

	// DQT, table 0 (luma) then table 1 (chrominance).
	dqt := make([]byte, 0, 130)
	dqt = append(dqt, 0x00)
	dqt = append(dqt, lumaQuant[:]...)
	dqt = append(dqt, 0x01)
	dqt = append(dqt, chromaQuant[:]...)
	enc.emitSegment(jpegDQT, dqt)

	// DRI.
	if restartEvery > 0 {
		var dri [2]byte
		binary.BigEndian.PutUint16(dri[:], uint16(restartEvery)) //nolint:gosec
		enc.emitSegment(jpegDRI, dri[:])
	}

	// SOF0.
	ySampling := byte(0x21)
	if sampling420 {
		ySampling = 0x22
	}
	sof := make([]byte, 0, 15)
	sof = append(sof, 8)
	sof = binary.BigEndian.AppendUint16(sof, uint16(height)) //nolint:gosec
	sof = binary.BigEndian.AppendUint16(sof, uint16(width))  //nolint:gosec
	sof = append(sof, 3, 1, ySampling, 0, 2, 0x11, 1, 3, 0x11, 1)
	enc.emitSegment(jpegSOF0, sof)

	// DHT: the four standard tables.
	enc.emitSegment(jpegDHT, append(append([]byte{0x00}, jpegLumaDCCodeLengths[:]...),
		jpegLumaDCSymbols[:]...))
	enc.emitSegment(jpegDHT, append(append([]byte{0x10}, jpegLumaACCodeLengths[:]...),
		jpegLumaACSymbols[:]...))
	enc.emitSegment(jpegDHT, append(append([]byte{0x01}, jpegChromaDCCodeLengths[:]...),
		jpegChromaDCSymbols[:]...))
	enc.emitSegment(jpegDHT, append(append([]byte{0x11}, jpegChromaACCodeLengths[:]...),
		jpegChromaACSymbols[:]...))

	// SOS.
	enc.emitSegment(jpegSOS, []byte{3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0})

	mcusX := width / 16
	mcusY := height / 16
	if !sampling420 {
		mcusY = height / 8 // 4:2:2 MCU is 16x8
	}

	for my := 0; my < mcusY; my++ {
		for mx := range mcusX {
			if restartEvery > 0 && enc.mcus > 0 && enc.mcus%restartEvery == 0 {
				enc.emitRestart()
				enc.prevDC = [3]int{}
			}
			enc.encodeMCU(img, mx, my, sampling420, lumaQuant, chromaQuant)
			enc.mcus++
		}
	}

	enc.flushBits()
	enc.emitMarker(jpegEOI)

	return enc.buf.Bytes()
}

// encodeMCU writes the 6 blocks (4:2:0) or 4 blocks (4:2:2) of one MCU.
func (e *jpegTestEncoder) encodeMCU(
	img *image.YCbCr,
	mx, my int,
	sampling420 bool,
	lumaQuant, chromaQuant [64]byte,
) {
	if sampling420 {
		// Four 8x8 luma blocks, one Cb and one Cr block.
		for dy := range 2 {
			for dx := range 2 {
				e.encodeBlock(
					jpegTestPlaneBlock(img.Y, img.YStride,
						mx*16+dx*8, my*16+dy*8),
					lumaQuant, 0, 0)
			}
		}
		e.encodeBlock(jpegTestPlaneBlock(img.Cb, img.CStride, mx*8, my*8),
			chromaQuant, 2, 1)
		e.encodeBlock(jpegTestPlaneBlock(img.Cr, img.CStride, mx*8, my*8),
			chromaQuant, 2, 2)

		return
	}

	// Two side-by-side 8x8 luma blocks, one Cb and one Cr block.
	for dx := range 2 {
		e.encodeBlock(
			jpegTestPlaneBlock(img.Y, img.YStride,
				mx*16+dx*8, my*8),
			lumaQuant, 0, 0)
	}
	e.encodeBlock(jpegTestPlaneBlock(img.Cb, img.CStride, mx*8, my*8),
		chromaQuant, 2, 1)
	e.encodeBlock(jpegTestPlaneBlock(img.Cr, img.CStride, mx*8, my*8),
		chromaQuant, 2, 2)
}

// jpegTestZigZag maps natural scan order onto zig-zag order.
//
//nolint:gochecknoglobals
var jpegTestZigZag = [64]uint8{
	0, 1, 8, 16, 9, 2, 3, 10,
	17, 24, 32, 25, 18, 11, 4, 5,
	12, 19, 26, 33, 40, 48, 41, 34,
	27, 20, 13, 6, 7, 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36,
	29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46,
	53, 60, 61, 54, 47, 55, 62, 63,
}

// jpegTestPlaneBlock extracts an 8x8 sample block, level-shifts to signed
// values and applies the forward DCT, returning natural-order coefficients.
func jpegTestPlaneBlock(plane []byte, stride, x, y int) [64]int32 {
	var samples [64]float64
	for dy := range 8 {
		for dx := range 8 {
			samples[dy*8+dx] = float64(plane[(y+dy)*stride+x+dx]) - 128
		}
	}

	var block [64]int32
	for v := range 8 {
		for u := range 8 {
			var sum float64
			for y0 := range 8 {
				for x0 := range 8 {
					sum += samples[y0*8+x0] *
						jpegTestCosine(u, x0) * jpegTestCosine(v, y0)
				}
			}
			alpha := jpegTestAlpha(u) * jpegTestAlpha(v)
			block[v*8+u] = int32(sum*alpha/4 + 0.5) //nolint:gosec
		}
	}

	return block
}

func jpegTestCosine(freq, sample int) float64 {
	// cos((2*x+1)*u*pi/16), memoized in a small table.
	type key struct{ f, s int }

	return jpegTestCosineCache[key{freq, sample}]
}

//
//nolint:gochecknoglobals
var jpegTestCosineCache = func() map[struct{ f, s int }]float64 {
	m := map[struct{ f, s int }]float64{}
	pi := math.Pi
	for f := range 8 {
		for s := range 8 {
			m[struct{ f, s int }{f, s}] = math.Cos(float64((2*s+1)*f) * pi / 16)
		}
	}

	return m
}()

func jpegTestAlpha(freq int) float64 {
	if freq == 0 {
		return 1 / 1.4142135623730951
	}

	return 1
}
