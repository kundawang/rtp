// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"slices"
)

// JPEGPayloader payloads JPEG frames according to RFC 2435.
//
// Only baseline sequential JPEG (SOF0) with the standard Annex K.3 Huffman
// tables and 4:2:2 or 4:2:0 chroma sampling is accepted. Restart markers
// (DRI) and quantization tables carried inside the JPEG frame are preserved
// and signaled through the RTP/JPEG headers.
type JPEGPayloader struct{}

// parsedJPEGFrame holds the parameters extracted from a complete JPEG frame.
type parsedJPEGFrame struct {
	width           int
	height          int
	baseType        byte // 0 for 4:2:2, 1 for 4:2:0
	restartInterval uint16
	lumaQuant       [64]byte
	chromaQuant     [64]byte
	hasLumaQuant    bool
	hasChromaQuant  bool
	scan            []byte // entropy-coded segment, excluding SOS header and EOI
	rstOffsets      []int  // byte offsets of RST markers within scan
}

// Payload fragments a JPEG frame across one or more RTP payloads. An
// unsupported or malformed JPEG frame produces no payloads; use
// parseJPEGFrame to obtain the concrete error.
func (p *JPEGPayloader) Payload(mtu uint16, payload []byte) [][]byte {
	frame, err := parseJPEGFrame(payload)
	if err != nil || mtu <= jpegMainHeaderSize {
		return nil
	}

	return fragmentJPEGFrame(frame, mtu)
}

// parseJPEGFrame parses the marker segments of an interchange-format JPEG
// frame and validates that every feature it uses is expressible in RFC 2435.
func parseJPEGFrame(data []byte) (*parsedJPEGFrame, error) { //nolint:cyclop
	if len(data) < 2 || data[0] != 0xFF || data[1] != jpegSOI {
		return nil, errJPEGMissingSOI
	}

	frame := &parsedJPEGFrame{}
	pos := 2

	for pos < len(data) {
		if data[pos] != 0xFF {
			return nil, errJPEGTruncatedSegment
		}
		// Skip any fill 0xFF bytes.
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}
		if pos >= len(data) {
			return nil, errJPEGTruncatedSegment
		}

		marker := data[pos]
		pos++

		// Standalone markers without a length field.
		if marker == jpegEOI {
			return nil, errJPEGTruncatedSegment
		}
		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			return nil, errJPEGRestartMarkerOutside
		}

		if pos+2 > len(data) {
			return nil, errJPEGTruncatedSegment
		}
		segmentLen := int(binary.BigEndian.Uint16(data[pos:]))
		if segmentLen < 2 || pos+segmentLen > len(data) {
			return nil, errJPEGTruncatedSegment
		}
		segment := data[pos+2 : pos+segmentLen]
		pos += segmentLen

		switch {
		case marker == jpegDQT:
			if err := parseJPEGDQT(segment, frame); err != nil {
				return nil, err
			}
		case marker == jpegDRI:
			if len(segment) < 2 {
				return nil, errJPEGTruncatedSegment
			}
			frame.restartInterval = binary.BigEndian.Uint16(segment[:2])
		case marker == jpegSOF0:
			if err := parseJPEGSOF(segment, frame); err != nil {
				return nil, err
			}
		case marker == jpegDHT:
			if err := validateJPEGDHT(segment); err != nil {
				return nil, err
			}
		case marker == jpegSOS:
			if frame.width == 0 || frame.height == 0 {
				return nil, errJPEGTruncatedSegment
			}
			if !frame.hasLumaQuant || !frame.hasChromaQuant {
				return nil, errJPEGMissingQuantization
			}
			if err := validateJPEGSOS(segment); err != nil {
				return nil, err
			}
			scan, rstOffsets, err := parseJPEGScanData(data[pos:], frame.restartInterval != 0)
			if err != nil {
				return nil, err
			}
			frame.scan = scan
			frame.rstOffsets = rstOffsets

			return frame, nil
		case isUnsupportedSOFMarker(marker):
			// SOF1..SOF15: extended sequential, progressive, lossless, ...
			return nil, errJPEGUnsupportedMode
		default:
			// APPn, COM, DAC and other tolerated marker segments are skipped.
		}
	}

	return nil, errJPEGTruncatedSegment
}

// isUnsupportedSOFMarker reports whether the marker is a start-of-frame
// marker other than the baseline SOF0.
func isUnsupportedSOFMarker(marker byte) bool {
	return marker >= 0xC0 && marker <= 0xCF &&
		marker != jpegSOF0 && marker != jpegDHT
}

func parseJPEGDQT(segment []byte, frame *parsedJPEGFrame) error {
	for len(segment) > 0 {
		if len(segment) < 1 {
			return errJPEGTruncatedSegment
		}
		pq := segment[0] >> 4 // precision: 0 = 8-bit, 1 = 16-bit
		tq := segment[0] & 0x0F
		segment = segment[1:]

		if pq != 0 {
			return errJPEGUnsupportedPrecision
		}
		if len(segment) < 64 {
			return errJPEGTruncatedSegment
		}

		switch tq {
		case 0:
			copy(frame.lumaQuant[:], segment[:64])
			frame.hasLumaQuant = true
		case 1:
			copy(frame.chromaQuant[:], segment[:64])
			frame.hasChromaQuant = true
		default:
			return errJPEGQuantTable
		}
		segment = segment[64:]
	}

	return nil
}

func parseJPEGSOF(segment []byte, frame *parsedJPEGFrame) error {
	// Layout: precision(1), height(2), width(2), component count(1), then
	// three component specs of identifier, sampling, quant table (3 each).
	if len(segment) < 6 {
		return errJPEGTruncatedSegment
	}
	if segment[0] != 8 {
		return errJPEGUnsupportedPrecision
	}

	height := int(binary.BigEndian.Uint16(segment[1:3]))
	width := int(binary.BigEndian.Uint16(segment[3:5]))
	if !validJPEGDimensions(width, height) {
		return errJPEGInvalidDimension
	}
	if segment[5] != 3 || len(segment) < 6+3*3 {
		return errJPEGUnsupportedSampling
	}

	// Component specs: identifier, sampling byte, quant table ID.
	ySampling, yQuant := segment[7], segment[8]
	cbSampling, cbQuant := segment[10], segment[11]
	crSampling, crQuant := segment[13], segment[14]

	baseType, ok := jpegSamplingType(ySampling, cbSampling, crSampling)
	if !ok {
		return errJPEGUnsupportedSampling
	}
	if yQuant != 0 || cbQuant != 1 || crQuant != 1 {
		return errJPEGQuantTable
	}

	frame.baseType = baseType
	frame.width = width
	frame.height = height

	return nil
}

func validJPEGDimensions(width, height int) bool {
	return width > 0 && height > 0 &&
		width <= jpegMaxDimension && height <= jpegMaxDimension &&
		width%8 == 0 && height%8 == 0
}

func jpegSamplingType(ySampling, cbSampling, crSampling byte) (byte, bool) {
	switch {
	case ySampling == 0x21 && cbSampling == 0x11 && crSampling == 0x11:
		return 0, true // 4:2:2
	case ySampling == 0x22 && cbSampling == 0x11 && crSampling == 0x11:
		return 1, true // 4:2:0
	default:
		return 0, false
	}
}

// validateJPEGDHT checks that every Huffman table segment matches the
// well-known Annex K.3 tables mandated by RFC 2435.
func validateJPEGDHT(segment []byte) error { //nolint:cyclop
	for len(segment) > 0 {
		if len(segment) < 17 {
			return errJPEGTruncatedSegment
		}
		tableClass := segment[0] >> 4
		tableID := segment[0] & 0x0F
		codeLengths := segment[1:17]
		symbolCount := 0
		for _, n := range codeLengths {
			symbolCount += int(n)
		}
		segment = segment[17:]
		if len(segment) < symbolCount {
			return errJPEGTruncatedSegment
		}
		symbols := segment[:symbolCount]
		segment = segment[symbolCount:]

		var wantLengths [16]byte
		copy(wantLengths[:], codeLengths)

		var wantSymbols []byte
		switch {
		case tableClass == 0 && tableID == 0:
			if wantLengths != jpegLumaDCCodeLengths {
				return errJPEGNonStandardHuffman
			}
			wantSymbols = jpegLumaDCSymbols[:]
		case tableClass == 1 && tableID == 0:
			if wantLengths != jpegLumaACCodeLengths {
				return errJPEGNonStandardHuffman
			}
			wantSymbols = jpegLumaACSymbols[:]
		case tableClass == 0 && tableID == 1:
			if wantLengths != jpegChromaDCCodeLengths {
				return errJPEGNonStandardHuffman
			}
			wantSymbols = jpegChromaDCSymbols[:]
		case tableClass == 1 && tableID == 1:
			if wantLengths != jpegChromaACCodeLengths {
				return errJPEGNonStandardHuffman
			}
			wantSymbols = jpegChromaACSymbols[:]
		default:
			return errJPEGNonStandardHuffman
		}

		if symbolCount != len(wantSymbols) || !slices.Equal(symbols, wantSymbols) {
			return errJPEGNonStandardHuffman
		}
	}

	return nil
}

//
//nolint:gochecknoglobals
var jpegExpectedSOS = [10]byte{3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0}

func validateJPEGSOS(segment []byte) error {
	// 1 component count byte, 3*2 component selector bytes, 3 scan bytes.
	if len(segment) != len(jpegExpectedSOS) {
		return errJPEGInvalidScan
	}

	var actual [10]byte
	copy(actual[:], segment)
	if actual != jpegExpectedSOS {
		return errJPEGInvalidScan
	}

	return nil
}

// scanMarkerAction describes how parseJPEGScanData handles a 0xFF byte.
type scanMarkerAction int

const (
	scanContinue scanMarkerAction = iota // advance by the returned count
	scanEnd                              // EOI found at markerOffset
	scanRestart                          // RST marker, record and advance
)

// inspectScanMarker is called with data[i] == 0xFF and classifies the marker
// that follows.
func inspectScanMarker(data []byte, i int, restartEnabled bool) (
	action scanMarkerAction, advance int, markerOffset int, err error,
) {
	if i+1 >= len(data) {
		return scanContinue, 0, 0, errJPEGTruncatedSegment
	}

	marker := data[i+1]
	switch {
	case marker == 0x00:
		return scanContinue, 2, 0, nil // byte stuffing
	case marker >= 0xD0 && marker <= 0xD7:
		if !restartEnabled {
			return scanContinue, 0, 0, errJPEGRestartMarkerOutside
		}

		return scanRestart, 2, i, nil
	case marker == jpegEOI:
		return scanEnd, 0, i, nil
	case marker == 0xFF:
		return scanContinue, 1, 0, nil // fill byte
	default:
		return scanContinue, 0, 0, errJPEGMarkerInScan
	}
}

// parseJPEGScanData returns the entropy-coded scan without the optional
// terminating EOI marker. Entropy 0xFF bytes are always followed by a stuffed
// 0x00; a 0xFF followed by another marker terminates the scan. RST markers
// (D0..D7) are retained and their offsets reported. Any other marker is
// rejected.
func parseJPEGScanData(data []byte, restartEnabled bool) ([]byte, []int, error) {
	rstOffsets := []int{}

	for i := 0; i < len(data); {
		if data[i] != 0xFF {
			i++

			continue
		}

		action, advance, markerOffset, err := inspectScanMarker(data, i, restartEnabled)
		if err != nil {
			return nil, nil, err
		}

		switch action {
		case scanEnd:
			return data[:markerOffset], rstOffsets, nil
		case scanRestart:
			rstOffsets = append(rstOffsets, markerOffset)
		case scanContinue:
			// No state to record; advance below.
		}
		i += advance
	}

	return data, rstOffsets, nil
}

// jpegFragment describes one RTP/JPEG packet's scan-data window.
type jpegFragment struct {
	offset       int
	length       int
	restartCount uint16
	firstChunk   bool
	lastChunk    bool
}

func fragmentJPEGFrame(frame *parsedJPEGFrame, mtu uint16) [][]byte {
	headerSize := jpegMainHeaderSize
	if frame.restartInterval != 0 {
		headerSize += jpegRestartHeaderSize
	}

	// Determine the quantization indicator and the optional in-band table,
	// which only rides in the first packet.
	quality, staticMatch := staticJPEGQuality(frame.lumaQuant, frame.chromaQuant)
	quantIndicator := byte(quality) //nolint:gosec // quality is in [1,99]
	quantHeader := []byte(nil)
	if !frame.hasLumaQuant || !frame.hasChromaQuant || !staticMatch {
		quantIndicator = jpegDynamicQ
		quantHeader = buildQuantHeader(frame)
	}

	// The first packet also carries the quantization header; reserve that
	// room so every emitted packet stays within the MTU.
	firstFragmentLimit := int(mtu) - headerSize - len(quantHeader)
	if firstFragmentLimit <= 0 || int(mtu)-headerSize <= 0 {
		return nil
	}

	fragments := splitJPEGScan(frame, int(mtu)-headerSize, firstFragmentLimit)
	assignRestartHeaders(fragments, frame)

	out := make([][]byte, 0, len(fragments))
	for i := range fragments {
		out = append(out, marshalJPEGFragment(frame, &fragments[i], headerSize,
			quantIndicator, quantHeader))
	}

	return out
}

func marshalJPEGFragment(
	frame *parsedJPEGFrame,
	frag *jpegFragment,
	headerSize int,
	quantIndicator byte,
	quantHeader []byte,
) []byte {
	payload := make([]byte, 0, headerSize+len(quantHeader)+frag.length)
	payload = appendMainHeader(payload, frame, quantIndicator, frag.offset)
	if frame.restartInterval != 0 {
		payload = appendRestartHeader(payload, frame.restartInterval, frag)
	}
	if frag.offset == 0 && quantHeader != nil {
		payload = append(payload, quantHeader...)
	}
	payload = append(payload, frame.scan[frag.offset:frag.offset+frag.length]...)

	return payload
}

// splitJPEGScan divides the entropy-coded scan into MTU-sized fragments.
// firstLimit bounds the first fragment, which must also make room for the
// in-band quantization table header; later fragments may use the full
// maxFragment. When restart markers are present every marker offset is a hard
// boundary, so a marker pair (0xFFDn) is never split across packets and each
// packet holds an integral number of restart intervals.
func splitJPEGScan(frame *parsedJPEGFrame, maxFragment, firstLimit int) []jpegFragment {
	boundaries := append(append([]int{}, frame.rstOffsets...), len(frame.scan))

	fragments := make([]jpegFragment, 0, len(frame.scan)/maxFragment+1)
	offset := 0
	first := true
	for offset < len(frame.scan) {
		limit := maxFragment
		if first {
			limit = firstLimit
		}

		cut := offset + limit
		if cut >= len(frame.scan) {
			fragments = append(fragments, jpegFragment{
				offset: offset,
				length: len(frame.scan) - offset,
			})

			break
		}

		// Choose the last restart boundary that still fits.
		next := cut
		for _, boundary := range boundaries {
			if boundary > offset && boundary <= cut {
				next = boundary
			}
		}
		if next == offset {
			// A single restart interval exceeds the available room; the
			// fallback restart header (count 0x3FFF) marks full reassembly.
			next = minInt(cut, len(frame.scan))
		}
		fragments = append(fragments, jpegFragment{offset: offset, length: next - offset})
		offset = next
		first = false
	}

	return fragments
}

// assignRestartHeaders fills the restart marker header fields. When every
// packet boundary coincides with a restart marker, the RFC chunk semantics
// (F/L bits and restart count) are used; otherwise the frame-wide fallback
// F=L=1, count=0x3FFF is emitted so the receiver reassembles before decoding.
func assignRestartHeaders(fragments []jpegFragment, frame *parsedJPEGFrame) {
	if frame.restartInterval == 0 {
		return
	}

	// The generic fallback is always valid.
	for i := range fragments {
		fragments[i].firstChunk = true
		fragments[i].lastChunk = true
		fragments[i].restartCount = jpegRestartCountMask
	}

	if len(frame.rstOffsets) == 0 {
		return
	}

	// A boundary set consists of offset 0, every restart marker offset and
	// the total scan length. Packet boundaries must be a subset.
	boundaries := make(map[int]struct{}, len(frame.rstOffsets)+2)
	boundaries[0] = struct{}{}
	for _, off := range frame.rstOffsets {
		boundaries[off] = struct{}{}
	}
	boundaries[len(frame.scan)] = struct{}{}

	for _, frag := range fragments {
		if _, ok := boundaries[frag.offset]; !ok {
			return
		}
	}

	// Precompute the restart count (index of the interval starting at the
	// marker) for every RST marker.
	markerCount := make(map[int]uint16, len(frame.rstOffsets))
	for idx, off := range frame.rstOffsets {
		count := uint16(idx + 1) // the marker separates interval idx and idx+1
		if count > jpegRestartCountMask {
			return
		}
		markerCount[off] = count
	}

	for i := range fragments {
		frag := &fragments[i]
		frag.firstChunk = true
		frag.lastChunk = true
		frag.restartCount = markerCount[frag.offset] // 0 for the first packet
	}
}

// buildQuantHeader serializes the two 8-bit quantization tables into the RFC
// 2435 quantization table header format.
func buildQuantHeader(frame *parsedJPEGFrame) []byte {
	tableData := make([]byte, 0, 128)
	tableData = append(tableData, frame.lumaQuant[:]...)
	tableData = append(tableData, frame.chromaQuant[:]...)

	header := make([]byte, 0, jpegQuantHeaderSize+128)
	header = append(header, 0, 0)                                          // MBZ and precision (both 8-bit tables)
	header = binary.BigEndian.AppendUint16(header, uint16(len(tableData))) //nolint:gosec
	header = append(header, tableData...)

	return header
}

func appendMainHeader(buf []byte, frame *parsedJPEGFrame, q byte, offset int) []byte {
	frameType := frame.baseType
	if frame.restartInterval != 0 {
		frameType |= jpegTypeRestart
	}

	buf = append(buf,
		0,                                               // type-specific: progressively scanned, no interlacing.
		byte(offset>>16), byte(offset>>8), byte(offset), //nolint:gosec
		frameType,
		q,
		byte(frame.width/8),  //nolint:gosec
		byte(frame.height/8), //nolint:gosec
	)

	return buf
}

func appendRestartHeader(buf []byte, interval uint16, frag *jpegFragment) []byte {
	flagsAndCount := frag.restartCount
	if frag.firstChunk {
		flagsAndCount |= 0x8000
	}
	if frag.lastChunk {
		flagsAndCount |= 0x4000
	}

	buf = binary.BigEndian.AppendUint16(buf, interval)
	buf = binary.BigEndian.AppendUint16(buf, flagsAndCount)

	return buf
}

// JPEGPacket represents the RFC 2435 RTP/JPEG header stored in an RTP payload.
type JPEGPacket struct {
	// TypeSpecific is the first header byte; zero (progressive scan) for the
	// payloader output, ignored on reassembly.
	TypeSpecific byte
	// FragmentOffset is the byte offset of this packet within the scan data.
	FragmentOffset uint32
	// Type is the raw RFC 2435 type byte (0/1, or 64/65 with restarts).
	Type byte
	// Q is the raw quantization indicator byte.
	Q      byte
	Width  uint16
	Height uint16

	// RestartInterval is zero when the frame has no restart markers.
	RestartInterval uint16
	RestartCount    uint16
	RestartFirst    bool
	RestartLast     bool

	// LumaQuant and ChromaQuant hold the in-band tables when Q >= 128, or the
	// tables derived from the static algorithm when Q < 128.
	LumaQuant   [64]byte
	ChromaQuant [64]byte

	// Payload is the raw entropy-coded fragment carried by this packet.
	Payload []byte

	// reassembly state
	headType   byte
	headQ      byte
	headWidth  byte
	headHeight byte
	fragments  map[uint32][]byte
	frameSize  uint32
	// sawFrameEnd is set when the fragment carrying the RTP marker bit has
	// been delivered through MarkFrameEnd. RFC 2435 defines frame completion
	// solely by that marker, so Flush requires it.
	sawFrameEnd bool
	frameEnd    uint32

	videoDepacketizer
}

// MarkFrameEnd records that the most recently supplied fragment carries the
// RTP marker bit and therefore terminates the current frame. Call this after
// Unmarshal when the RTP header marker bit is set; Flush requires it.
func (p *JPEGPacket) MarkFrameEnd() {
	p.sawFrameEnd = true
	p.frameEnd = p.frameSize
}

// Unmarshal parses an RFC 2435 RTP/JPEG payload and buffers the fragment for
// reassembly. It returns an empty (non-nil) slice while the frame is still
// incomplete and the complete, decodable JPEG once the frame is assembled via
// Flush (driven by the RTP marker bit through IsDetectedFinalPacketInSequence).
func (p *JPEGPacket) Unmarshal(payload []byte) ([]byte, error) { //nolint:cyclop
	hdr, err := p.parseHeader(payload)
	if err != nil {
		return nil, err
	}
	scan := hdr.scan

	if p.fragments == nil {
		p.fragments = map[uint32][]byte{}
	}

	switch {
	case hdr.FragmentOffset == 0:
		// A new frame starts: discard anything buffered for the previous one.
		p.resetFrame(hdr)
	case len(p.fragments) == 0:
		return nil, errJPEGIncompleteFrame
	case hdr.Type != p.headType || hdr.Q != p.headQ ||
		hdr.rawWidth != p.headWidth || hdr.rawHeight != p.headHeight ||
		hdr.restartInterval != p.RestartInterval:
		return nil, errJPEGHeaderMismatch
	}

	// Per-packet metadata, in the style of the other video depacketizers.
	p.FragmentOffset = hdr.FragmentOffset
	p.Payload = scan
	p.RestartCount = hdr.restartCount
	p.RestartFirst = hdr.restartFirst
	p.RestartLast = hdr.restartLast

	end := hdr.FragmentOffset + uint32(len(scan)) //nolint:gosec // bounded by MTU
	if end > 1<<24 {
		return nil, errJPEGOffsetTooLarge
	}
	if len(scan) == 0 {
		return nil, errJPEGShortPacket
	}

	if err := p.checkFragment(hdr.FragmentOffset, end); err != nil {
		return nil, err
	}

	p.fragments[hdr.FragmentOffset] = append([]byte(nil), scan...)
	if end > p.frameSize {
		p.frameSize = end
	}

	return []byte{}, nil
}

func (p *JPEGPacket) checkFragment(offset, end uint32) error {
	// Reject exact duplicates and any overlapping fragment against the
	// intervals already buffered. Adjacent fragments (off == existingEnd)
	// are valid.
	for off := range p.fragments {
		if off == offset {
			return errJPEGDuplicateFragment
		}
		existingEnd := off + uint32(len(p.fragments[off])) //nolint:gosec
		if offset < existingEnd && end > off {
			return errJPEGOverlappingFragment
		}
	}

	return nil
}

// jpegParsedHeader carries the fields extracted from one RTP/JPEG payload.
type jpegParsedHeader struct {
	TypeSpecific    byte
	FragmentOffset  uint32
	Type            byte
	Q               byte
	rawWidth        byte
	rawHeight       byte
	restartInterval uint16
	restartCount    uint16
	restartFirst    bool
	restartLast     bool
	lumaQuant       [64]byte
	chromaQuant     [64]byte
	scan            []byte
}

func (p *JPEGPacket) parseHeader(payload []byte) (*jpegParsedHeader, error) { //nolint:cyclop
	if len(payload) < jpegMainHeaderSize {
		return nil, errJPEGShortPacket
	}

	hdr := &jpegParsedHeader{
		TypeSpecific:   payload[0],
		FragmentOffset: uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
		Type:           payload[4],
		Q:              payload[5],
		rawWidth:       payload[6],
		rawHeight:      payload[7],
	}

	baseType := hdr.Type &^ jpegTypeRestart
	if baseType > 1 || hdr.Type >= 128 {
		return nil, errJPEGInvalidType
	}
	if hdr.rawWidth == 0 || hdr.rawHeight == 0 {
		return nil, errJPEGInvalidDimension
	}

	pos := jpegMainHeaderSize
	if hdr.Type&jpegTypeRestart != 0 {
		if pos+jpegRestartHeaderSize > len(payload) {
			return nil, errJPEGRestartMissing
		}
		hdr.restartInterval = binary.BigEndian.Uint16(payload[pos:])
		if hdr.restartInterval == 0 {
			return nil, errJPEGRestartIntervalZero
		}
		flagsCount := binary.BigEndian.Uint16(payload[pos+2:])
		hdr.restartFirst = flagsCount&0x8000 != 0
		hdr.restartLast = flagsCount&0x4000 != 0
		hdr.restartCount = flagsCount & jpegRestartCountMask
		pos += jpegRestartHeaderSize
	}

	if hdr.Q >= 128 {
		newPos, err := parseJPEGQuantHeader(payload, hdr, pos)
		if err != nil {
			return nil, err
		}
		pos = newPos
	} else {
		if hdr.Q < 1 || hdr.Q > 99 {
			return nil, errJPEGInvalidQ
		}
		hdr.lumaQuant, hdr.chromaQuant = makeJPEGStaticTables(int(hdr.Q))
	}

	if hdr.scan == nil {
		hdr.scan = payload[pos:]
	}

	return hdr, nil
}

// parseJPEGQuantHeader consumes the in-band quantization table header from a
// frame-head packet. Non-head packets (fragment offset != 0) contain scan
// data immediately after the preceding headers. It returns the new read
// position.
func parseJPEGQuantHeader(payload []byte, hdr *jpegParsedHeader, pos int) (int, error) {
	if hdr.FragmentOffset != 0 {
		// The quantization table header may only appear in the first packet;
		// subsequent packets carry scan data immediately.
		return pos, nil
	}
	if pos+jpegQuantHeaderSize > len(payload) {
		return pos, errJPEGQuantLength
	}
	mbz := payload[pos]
	precision := payload[pos+1]
	tableLen := int(binary.BigEndian.Uint16(payload[pos+2:]))
	pos += jpegQuantHeaderSize
	if mbz != 0 {
		return pos, errJPEGQuantTable
	}
	if pos+tableLen > len(payload) {
		return pos, errJPEGQuantLength
	}
	// RFC 2435 permits a zero length when tables are provisioned out-of-band,
	// but this implementation has no such channel: accepting it would yield a
	// frame with empty quantization tables.
	if tableLen == 0 {
		return pos, errJPEGQuantTable
	}
	if err := parseInBandQuantTables(payload[pos:pos+tableLen], precision, hdr); err != nil {
		return pos, err
	}

	return pos + tableLen, nil
}

func parseInBandQuantTables(tableData []byte, precision byte, hdr *jpegParsedHeader) error {
	if precision != 0 {
		return errJPEGUnsupportedPrecision
	}
	if len(tableData) != 128 {
		return errJPEGQuantTable
	}
	copy(hdr.lumaQuant[:], tableData[:64])
	copy(hdr.chromaQuant[:], tableData[64:])

	return nil
}

func (p *JPEGPacket) resetFrame(hdr *jpegParsedHeader) {
	p.TypeSpecific = hdr.TypeSpecific
	p.Type = hdr.Type
	p.Q = hdr.Q
	p.headType = hdr.Type
	p.headQ = hdr.Q
	p.headWidth = hdr.rawWidth
	p.headHeight = hdr.rawHeight
	p.Width = uint16(hdr.rawWidth) * 8
	p.Height = uint16(hdr.rawHeight) * 8
	p.RestartInterval = hdr.restartInterval
	p.RestartCount = hdr.restartCount
	p.RestartFirst = hdr.restartFirst
	p.RestartLast = hdr.restartLast
	p.LumaQuant = hdr.lumaQuant
	p.ChromaQuant = hdr.chromaQuant
	p.fragments = map[uint32][]byte{}
	p.frameSize = 0
	p.sawFrameEnd = false
	p.frameEnd = 0
}

// IsDetectedFinalPacketInSequence reports whether the packet carrying the
// supplied RTP marker bit ends a JPEG frame, mirroring the H264 depacketizer.
func (p *JPEGPacket) IsDetectedFinalPacketInSequence(rtpPacketMarkerBit bool) bool {
	return rtpPacketMarkerBit
}

// Flush assembles the buffered fragments into a complete, interchange-format
// JPEG image. Frame completion requires the marked final packet to have been
// signaled with MarkFrameEnd; otherwise errJPEGIncompleteFrame is returned.
// Reassembly state is reset in every case.
func (p *JPEGPacket) Flush() ([]byte, error) {
	defer func() {
		p.fragments = nil
		p.frameSize = 0
		p.sawFrameEnd = false
		p.frameEnd = 0
	}()

	if len(p.fragments) == 0 || !p.sawFrameEnd {
		return nil, errJPEGIncompleteFrame
	}

	offsets := make([]uint32, 0, len(p.fragments))
	for off := range p.fragments {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)

	scan := make([]byte, 0, p.frameEnd)
	var next uint32
	for _, off := range offsets {
		if off != next {
			return nil, errJPEGIncompleteFrame
		}
		scan = append(scan, p.fragments[off]...)
		next = off + uint32(len(p.fragments[off])) //nolint:gosec // lengths bounded by MTU and 2^24
	}
	// Every byte up to the marked final fragment must be covered.
	if next != p.frameEnd {
		return nil, errJPEGIncompleteFrame
	}

	baseType := p.headType &^ jpegTypeRestart
	headers := buildJPEGHeaders(
		baseType, int(p.Width), int(p.Height),
		p.LumaQuant, p.ChromaQuant, p.RestartInterval,
	)

	jpegFrame := make([]byte, 0, len(headers)+len(scan)+2)
	jpegFrame = append(jpegFrame, headers...)
	jpegFrame = append(jpegFrame, scan...)
	jpegFrame = append(jpegFrame, 0xFF, jpegEOI)

	return jpegFrame, nil
}

// IsPartitionHead reports whether the payload is the first fragment of a
// JPEG frame (fragment offset zero).
func (*JPEGPacket) IsPartitionHead(payload []byte) bool {
	if len(payload) < jpegMainHeaderSize {
		return false
	}

	return payload[1] == 0 && payload[2] == 0 && payload[3] == 0
}
