// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "encoding/binary"

const (
	// JPEG markers (ITU-T T.81).
	jpegSOI  = 0xD8
	jpegEOI  = 0xD9
	jpegDHT  = 0xC4
	jpegDRI  = 0xDD
	jpegSOF0 = 0xC0
	jpegDQT  = 0xDB
	jpegSOS  = 0xDA

	// RFC 2435 main JPEG header size.
	jpegMainHeaderSize = 8
	// RFC 2435 restart marker header size.
	jpegRestartHeaderSize = 4
	// RFC 2435 quantization table header size.
	jpegQuantHeaderSize = 4

	// jpegTypeRestart is ORed into the type number when restart markers are
	// present in the JPEG scan data.
	jpegTypeRestart = 0x40

	// jpegDynamicQ is the dynamic quantization indicator (Q >= 128). The
	// payloader always emits the dynamic value 255 because it attaches the
	// tables in-band on every frame.
	jpegDynamicQ = 255

	// jpegRestartCountMask covers the 14-bit restart count field.
	jpegRestartCountMask = 0x3FFF

	// jpegMaxDimension is the largest image dimension expressible in the
	// 8-bit, 8-pixel-block width/height header fields (255*8).
	jpegMaxDimension = 2040
)

// appendMarkerSegment writes a marker plus its payload (without the marker
// prefix) and fills in the 16-bit segment length.
func appendMarkerSegment(buf []byte, marker byte, payload []byte) []byte {
	buf = append(buf, 0xFF, marker)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload)+2)) // nolint:gosec
	buf = append(buf, payload...)

	return buf
}

// appendDQT writes one 8-bit DQT segment for the given table identifier.
func appendDQT(buf []byte, tableID byte, table [64]byte) []byte {
	payload := make([]byte, 0, 65)
	payload = append(payload, tableID&0x0F)
	payload = append(payload, table[:]...)

	return appendMarkerSegment(buf, jpegDQT, payload)
}

// appendDHT writes one Huffman table definition segment.
func appendDHT(
	buf []byte,
	tableClass, tableID byte,
	codeLengths [16]byte,
	symbols []byte,
) []byte {
	payload := make([]byte, 0, 1+16+len(symbols))
	payload = append(payload, (tableClass<<4)|(tableID&0x0F))
	payload = append(payload, codeLengths[:]...)
	payload = append(payload, symbols...)

	return appendMarkerSegment(buf, jpegDHT, payload)
}

// buildJPEGHeaders regenerates the marker segments that RFC 2435 omits from
// the RTP payload (Appendix B MakeHeaders): DQT, optional DRI, SOF0, the four
// Annex K.3 DHT segments and SOS. SOI is prepended as well; the scan data and
// a terminating EOI are added by the caller.
func buildJPEGHeaders( //nolint:cyclop
	frameType byte,
	width, height int,
	lumaQuant, chromaQuant [64]byte,
	restartInterval uint16,
) []byte {
	buf := make([]byte, 0, 400)

	// SOI
	buf = append(buf, 0xFF, jpegSOI)

	// DQT: table 0 (luminance), then table 1 (chrominance).
	buf = appendDQT(buf, 0, lumaQuant)
	buf = appendDQT(buf, 1, chromaQuant)

	// DRI, only when the frame carries restart markers.
	if restartInterval != 0 {
		dri := make([]byte, 2)
		binary.BigEndian.PutUint16(dri, restartInterval)
		buf = appendMarkerSegment(buf, jpegDRI, dri)
	}

	// SOF0: baseline DCT, 8-bit precision, 3 components.
	sof := make([]byte, 0, 15)
	sof = append(sof, 8)                                     // precision
	sof = binary.BigEndian.AppendUint16(sof, uint16(height)) // nolint:gosec
	sof = binary.BigEndian.AppendUint16(sof, uint16(width))  // nolint:gosec
	sof = append(sof, 3)                                     // number of components

	// Component 1 (Y): sampling 0x21 for type 0 (4:2:2), 0x22 for type 1
	// (4:2:0); quant table 0.
	if frameType == 0 {
		sof = append(sof, 1, 0x21, 0)
	} else {
		sof = append(sof, 1, 0x22, 0)
	}
	// Components 2 (Cb) and 3 (Cr): 1x1 sampling, quant table 1.
	sof = append(sof, 2, 0x11, 1, 3, 0x11, 1)
	buf = appendMarkerSegment(buf, jpegSOF0, sof)

	// DHT: the four standard Annex K.3 tables.
	buf = appendDHT(buf, 0, 0, jpegLumaDCCodeLengths, jpegLumaDCSymbols[:])
	buf = appendDHT(buf, 1, 0, jpegLumaACCodeLengths, jpegLumaACSymbols[:])
	buf = appendDHT(buf, 0, 1, jpegChromaDCCodeLengths, jpegChromaDCSymbols[:])
	buf = appendDHT(buf, 1, 1, jpegChromaACCodeLengths, jpegChromaACSymbols[:])

	// SOS: 3 components with the standard table selector pairing.
	sos := make([]byte, 0, 12)
	sos = append(sos, 3)
	sos = append(sos, 1, 0x00, 2, 0x11, 3, 0x11)
	sos = append(sos, 0, 63, 0) // spectral selection 0..63, no approximation
	buf = appendMarkerSegment(buf, jpegSOS, sos)

	return buf
}
