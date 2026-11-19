// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"fmt"
)

// MPEG4GenericMode selects the MPEG4-generic RTP payload mode defined in RFC 3640, section 3.3.
type MPEG4GenericMode uint8

const (
	// MPEG4ModeAACLBR is the AAC-lbr mode (RFC 3640 section 3.3.5): 8-bit AU-headers,
	// maximum AU size 63 octets and fragmentation forbidden.
	MPEG4ModeAACLBR MPEG4GenericMode = iota

	// MPEG4ModeAACHBR is the AAC-hbr mode (RFC 3640 section 3.3.6): 16-bit AU-headers,
	// maximum AU size 8191 octets and fragmentation permitted.
	MPEG4ModeAACHBR
)

const (
	// mpeg4AUHeadersLengthSize is the 16-bit AU-headers-length field in octets.
	mpeg4AUHeadersLengthSize = 2

	// AU-header bit widths mandated by RFC 3640 for the two AAC modes.
	aaclbrSizeLength       = 6
	aaclbrIndexLength      = 2
	aaclbrIndexDeltaLength = 2
	aachbrSizeLength       = 13
	aachbrIndexLength      = 3
	aachbrIndexDeltaLength = 3

	// Maximum access unit sizes allowed by the size field of each mode.
	aaclbrMaxAUSize = 1<<aaclbrSizeLength - 1 // 63
	aachbrMaxAUSize = 1<<aachbrSizeLength - 1 // 8191

	// mpeg4SeqBackwardsThreshold is half of the 16-bit RTP sequence number space.
	// A modular difference above it means the new sequence number is older.
	mpeg4SeqBackwardsThreshold = 1 << 15
)

// MPEG4AudioPayloader implements the RFC 3640 MPEG4-generic RTP payload format
// for AAC access units.
//
// Multiple complete access units sharing one RTP timestamp are bundled into a
// single packet through PayloadAUs, while access units larger than what fits in
// one packet are fragmented across consecutive RTP packets (AAC-hbr only).
type MPEG4AudioPayloader struct {
	// Mode is the MPEG4-generic mode, AAC-lbr or AAC-hbr.
	Mode MPEG4GenericMode

	// SizeLength, IndexLength and IndexDeltaLength are the AU-header field widths
	// in bits, as signaled with the MIME parameters of the same names. They must
	// match the selected mode (6/2/2 for AAC-lbr and 13/3/3 for AAC-hbr).
	SizeLength       int
	IndexLength      int
	IndexDeltaLength int
}

// NewMPEG4AudioPayloader returns a payloader configured for the given mode with
// the AU-header bit widths mandated by RFC 3640.
func NewMPEG4AudioPayloader(mode MPEG4GenericMode) (*MPEG4AudioPayloader, error) {
	payloader := &MPEG4AudioPayloader{Mode: mode}
	if err := payloader.applyModeDefaults(); err != nil {
		return nil, err
	}

	return payloader, nil
}

func mpeg4ModeDefaults(mode MPEG4GenericMode) (int, int, int, error) {
	switch mode {
	case MPEG4ModeAACLBR:
		return aaclbrSizeLength, aaclbrIndexLength, aaclbrIndexDeltaLength, nil
	case MPEG4ModeAACHBR:
		return aachbrSizeLength, aachbrIndexLength, aachbrIndexDeltaLength, nil
	default:
		return 0, 0, 0, fmt.Errorf("%w: %d", errMPEG4BadMode, mode)
	}
}

func (p *MPEG4AudioPayloader) applyModeDefaults() error {
	if p.SizeLength == 0 && p.IndexLength == 0 && p.IndexDeltaLength == 0 {
		sizeLength, indexLength, indexDeltaLength, err := mpeg4ModeDefaults(p.Mode)
		if err != nil {
			return err
		}

		p.SizeLength, p.IndexLength, p.IndexDeltaLength = sizeLength, indexLength, indexDeltaLength
	}

	return p.validateConfig()
}

func (p *MPEG4AudioPayloader) validateConfig() error {
	sizeLength, indexLength, indexDeltaLength, err := mpeg4ModeDefaults(p.Mode)
	if err != nil {
		return err
	}

	if p.SizeLength != sizeLength || p.IndexLength != indexLength || p.IndexDeltaLength != indexDeltaLength {
		return fmt.Errorf(
			"%w: mode %d requires sizeLength=%d indexLength=%d indexDeltaLength=%d, got %d/%d/%d",
			errMPEG4BadConfig, p.Mode,
			sizeLength, indexLength, indexDeltaLength,
			p.SizeLength, p.IndexLength, p.IndexDeltaLength,
		)
	}

	return nil
}

func (p *MPEG4AudioPayloader) maxAUSize() int {
	if p.Mode == MPEG4ModeAACLBR {
		return aaclbrMaxAUSize
	}

	return aachbrMaxAUSize
}

// headerBits is the width in bits of one AU-header. Every AU-header of a stream
// uses the same width; continuation fragments keep the full header (RFC 3640
// section 3.2.3.1), with AU-Index coded 0 and AU-size naming the whole AU.
func (p *MPEG4AudioPayloader) headerBits() int {
	return p.SizeLength + p.IndexLength
}

// Payload packetizes a single access unit and satisfies the Payloader interface
// so the payloader works with the existing rtp.Packetizer. Configuration errors
// and access units that cannot be packetized are reported through PayloadAUs and
// result in no payloads here.
func (p *MPEG4AudioPayloader) Payload(mtu uint16, payload []byte) [][]byte {
	payloads, err := p.PayloadAUs(mtu, [][]byte{payload})
	if err != nil {
		return [][]byte{}
	}

	return payloads
}

// PayloadAUs packetizes one or more access units that share the same RTP
// timestamp. The access units keep their order, and the n-th AU-header describes
// the n-th access unit in data-section order.
func (p *MPEG4AudioPayloader) PayloadAUs(mtu uint16, aus [][]byte) ([][]byte, error) {
	if err := p.applyModeDefaults(); err != nil {
		return nil, err
	}

	if err := p.validateAUs(aus); err != nil {
		return nil, err
	}

	// The first fragment/complete AU of a packet always carries an AU-Index field.
	headerOverhead := mpeg4AUHeadersLengthSize + (p.headerBits()+7)/8
	maxDataPerPacket := int(mtu) - headerOverhead
	if maxDataPerPacket <= 0 {
		return nil, fmt.Errorf("%w: MTU %d cannot hold the AU header", errMPEG4AUTooLarge, mtu)
	}

	return p.packetize(aus, maxDataPerPacket)
}

func (p *MPEG4AudioPayloader) validateAUs(aus [][]byte) error {
	for _, au := range aus {
		if len(au) > 0 && len(au) > p.maxAUSize() {
			return fmt.Errorf("%w: %d octets", errMPEG4AUTooLarge, len(au))
		}
	}

	return nil
}

// packetize greedily bundles complete access units and only splits an access
// unit across packets when a single one no longer fits whole.
func (p *MPEG4AudioPayloader) packetize(aus [][]byte, maxDataPerPacket int) ([][]byte, error) {
	payloads := [][]byte{}
	bundled := [][]byte{}
	bundledSize := 0

	flush := func() {
		if len(bundled) == 0 {
			return
		}

		payloads = append(payloads, p.buildCompletePacket(bundled))
		bundled = [][]byte{}
		bundledSize = 0
	}

	for _, au := range aus {
		if len(au) == 0 {
			continue
		}

		if len(au) > maxDataPerPacket {
			// A complete AU no longer fits: emit everything bundled so far first.
			flush()

			fragments, err := p.fragmentOrReject(au, maxDataPerPacket)
			if err != nil {
				return nil, err
			}

			payloads = append(payloads, fragments...)

			continue
		}

		// Adding another AU means an extra IndexDeltaLength-bit header plus the
		// AU data itself.
		extra := len(au)
		if len(bundled) > 0 {
			extra += (p.IndexDeltaLength + 7) / 8
		}

		if bundledSize+extra > maxDataPerPacket {
			flush()
		}

		bundled = append(bundled, au)
		bundledSize += extra
	}

	flush()

	return payloads, nil
}

func (p *MPEG4AudioPayloader) fragmentOrReject(au []byte, maxDataPerPacket int) ([][]byte, error) {
	if p.Mode == MPEG4ModeAACLBR {
		return nil, fmt.Errorf(
			"%w: AAC-lbr cannot fragment an AU of %d octets",
			errMPEG4AUTooLarge, len(au),
		)
	}

	return p.fragmentAU(au, maxDataPerPacket)
}

// buildCompletePacket builds an RTP packet carrying one or more complete access
// units. The first AU-header carries AU-Index 0; following headers carry an
// AU-Index-delta of 0, which marks consecutive access units.
func (p *MPEG4AudioPayloader) buildCompletePacket(aus [][]byte) []byte {
	headers := newBitWriter()
	for i, au := range aus {
		headers.write(uint64(len(au)), p.SizeLength)
		if i == 0 {
			headers.write(0, p.IndexLength)
		} else {
			headers.write(0, p.IndexDeltaLength)
		}
	}

	headerBytes := headers.bytes()
	out := make([]byte, 0, mpeg4AUHeadersLengthSize+len(headerBytes)+totalAUSize(aus))
	out = binary.BigEndian.AppendUint16(out, uint16(len(headerBytes)*8)) //nolint:gosec
	out = append(out, headerBytes...)
	for _, au := range aus {
		out = append(out, au...)
	}

	return out
}

// fragmentAU splits an access unit larger than one packet across consecutive RTP
// packets. Every packet carries one full AU-header describing the whole AU with
// AU-Index 0, as required by RFC 3640 section 3.2.3.1.
func (p *MPEG4AudioPayloader) fragmentAU(au []byte, maxDataPerPacket int) ([][]byte, error) {
	fragments := [][]byte{}
	headerBytes := (p.headerBits() + 7) / 8

	for offset := 0; offset < len(au); {
		size := minInt(maxDataPerPacket, len(au)-offset)
		if size <= 0 {
			return nil, fmt.Errorf("%w: fragment would be empty", errMPEG4AUTooLarge)
		}

		headers := newBitWriter()
		// AU-size names the entire access unit, not the fragment.
		headers.write(uint64(len(au)), p.SizeLength)
		headers.write(0, p.IndexLength)

		out := make([]byte, 0, mpeg4AUHeadersLengthSize+headerBytes+size)
		out = binary.BigEndian.AppendUint16(out, uint16(headerBytes*8)) //nolint:gosec
		out = append(out, headers.bytes()...)
		out = append(out, au[offset:offset+size]...)
		fragments = append(fragments, out)

		offset += size
	}

	return fragments, nil
}

func totalAUSize(aus [][]byte) int {
	total := 0
	for _, au := range aus {
		total += len(au)
	}

	return total
}

// bitWriter packs unsigned values into an MSB-first bit stream, as used by the
// AU Header Section of RFC 3640.
type bitWriter struct {
	bits []byte
	used int
}

func newBitWriter() *bitWriter {
	return &bitWriter{}
}

func (w *bitWriter) write(value uint64, width int) {
	for i := width - 1; i >= 0; i-- {
		bit := byte((value >> uint(i)) & 1)
		byteIndex := w.used / 8
		if w.used%8 == 0 {
			w.bits = append(w.bits, 0)
		}

		w.bits[byteIndex] |= bit << (7 - w.used%8)
		w.used++
	}
}

func (w *bitWriter) bytes() []byte {
	return w.bits
}

// MPEG4AudioPacket depacketizes RFC 3640 MPEG4-generic RTP payloads carrying AAC
// access units.
//
// Fragments of a large access unit are buffered until the final fragment
// arrives. Unmarshal works on RTP payloads alone; UnmarshalRTP additionally
// validates the RTP sequence number, timestamp and marker bit and gives explicit
// results for out-of-order packets, timestamp jumps and missing fragments.
type MPEG4AudioPacket struct {
	// Mode is the MPEG4-generic mode, AAC-lbr or AAC-hbr.
	Mode MPEG4GenericMode

	// SizeLength, IndexLength and IndexDeltaLength are the AU-header field widths
	// in bits and must match the selected mode.
	SizeLength       int
	IndexLength      int
	IndexDeltaLength int

	// ConstantDuration, when non-zero, is the number of RTP timestamp ticks
	// expected between consecutive (non-fragmented) access units. A smaller
	// positive step is reported as a timestamp jump.
	ConstantDuration uint32

	// AUs holds the complete access units delivered by the last successful
	// Unmarshal call, in transmission order.
	AUs [][]byte

	// Fragmented is true while the packet is reassembling a fragmented access unit.
	Fragmented bool

	fragmentBuffer []byte
	expectedAUSize int

	head bool
	tail bool

	lastSeq       uint16
	hasLastSeq    bool
	lastTimestamp uint32
	hasTimestamp  bool
}

// NewMPEG4AudioPacket returns a depacketizer configured for the given mode with
// the AU-header bit widths mandated by RFC 3640.
func NewMPEG4AudioPacket(mode MPEG4GenericMode) (*MPEG4AudioPacket, error) {
	packet := &MPEG4AudioPacket{Mode: mode}
	if err := packet.applyModeDefaults(); err != nil {
		return nil, err
	}

	return packet, nil
}

func (p *MPEG4AudioPacket) applyModeDefaults() error {
	if p.SizeLength == 0 && p.IndexLength == 0 && p.IndexDeltaLength == 0 {
		sizeLength, indexLength, indexDeltaLength, err := mpeg4ModeDefaults(p.Mode)
		if err != nil {
			return err
		}

		p.SizeLength, p.IndexLength, p.IndexDeltaLength = sizeLength, indexLength, indexDeltaLength
	}

	return p.validateConfig()
}

func (p *MPEG4AudioPacket) validateConfig() error {
	sizeLength, indexLength, indexDeltaLength, err := mpeg4ModeDefaults(p.Mode)
	if err != nil {
		return err
	}

	if p.SizeLength != sizeLength || p.IndexLength != indexLength || p.IndexDeltaLength != indexDeltaLength {
		return fmt.Errorf("%w: mode %d requires %d/%d/%d bit widths",
			errMPEG4BadConfig, p.Mode, sizeLength, indexLength, indexDeltaLength)
	}

	return nil
}

func (p *MPEG4AudioPacket) headerBits() int {
	return p.SizeLength + p.IndexLength
}

// Unmarshal parses an RTP payload (without the RTP header). Complete access
// units are returned concatenated and also stored in AUs; fragment packets
// extend the internal reassembly buffer and return an empty slice until the
// final fragment completes the access unit.
func (p *MPEG4AudioPacket) Unmarshal(payload []byte) ([]byte, error) {
	if err := p.applyModeDefaults(); err != nil {
		return nil, err
	}

	if payload == nil {
		return nil, errMPEG4NilPacket
	}

	p.AUs = nil
	p.head = false
	p.tail = false

	if len(payload) < mpeg4AUHeadersLengthSize {
		return nil, errMPEG4ShortPacket
	}

	headerLengthBits := int(binary.BigEndian.Uint16(payload[:2]))
	if headerLengthBits == 0 {
		return nil, fmt.Errorf("%w: AU-headers-length must be positive", errMPEG4Truncated)
	}

	// The section is octet-aligned: AU-headers-length counts the header bits
	// excluding up to 7 zero-padding bits, so the on-wire section rounds up.
	headerSectionBytes := (headerLengthBits + 7) / 8
	dataStart := mpeg4AUHeadersLengthSize + headerSectionBytes
	if len(payload) < dataStart+1 || headerLengthBits < p.headerBits() {
		return nil, errMPEG4Truncated
	}

	// Only single-header packets can carry a fragment; figure out how many
	// AU-headers the section holds before touching the data section.
	headers, err := p.parseAUHeaders(payload[mpeg4AUHeadersLengthSize:dataStart], headerLengthBits)
	if err != nil {
		return nil, err
	}

	data := payload[dataStart:]
	if len(headers) == 1 {
		return p.handleSingleHeader(headers[0], data)
	}

	return p.handleMultipleHeaders(headers, data)
}

type mpeg4AUHeader struct {
	size  int
	index int
}

func (p *MPEG4AudioPacket) parseAUHeaders(section []byte, totalBits int) ([]mpeg4AUHeader, error) {
	reader := newBitReader(section)
	headers := []mpeg4AUHeader{}
	consumed := 0

	for consumed < totalBits {
		headerWidth := p.SizeLength + p.IndexLength
		if len(headers) > 0 {
			headerWidth = p.SizeLength + p.IndexDeltaLength
		}

		// Up to 7 zero-padding bits may octet-align the section (RFC 3640
		// section 3.2.1); fewer bits than a full AU-header must be padding.
		if totalBits-consumed < headerWidth {
			if err := reader.skipPadding(totalBits - consumed); err != nil {
				return nil, err
			}

			consumed = totalBits

			break
		}

		header, headerBits, err := p.readNextHeader(reader, len(headers))
		if err != nil {
			return nil, err
		}

		headers = append(headers, header)
		consumed += headerBits
	}

	// Only the declared bits must be consumed; any extra physical bits are the
	// octet-alignment padding of the section and were already validated above.
	if consumed != totalBits {
		return nil, errMPEG4Truncated
	}

	return headers, nil
}

func (p *MPEG4AudioPacket) readNextHeader(
	reader *bitReader,
	headerCount int,
) (mpeg4AUHeader, int, error) {
	size, err := reader.read(p.SizeLength)
	if err != nil {
		return mpeg4AUHeader{}, 0, fmt.Errorf("%w: AU-size", errMPEG4Truncated)
	}

	var index int
	if headerCount == 0 {
		index, err = reader.read(p.IndexLength)
		if err != nil {
			return mpeg4AUHeader{}, 0, fmt.Errorf("%w: AU-Index", errMPEG4Truncated)
		}

		if index != 0 {
			return mpeg4AUHeader{}, 0, fmt.Errorf("%w: got %d", errMPEG4IllegalIndex, index)
		}

		return mpeg4AUHeader{size: size, index: index}, p.SizeLength + p.IndexLength, nil
	}

	index, err = reader.read(p.IndexDeltaLength)
	if err != nil {
		return mpeg4AUHeader{}, 0, fmt.Errorf("%w: AU-Index-delta", errMPEG4Truncated)
	}

	return mpeg4AUHeader{size: size, index: index}, p.SizeLength + p.IndexDeltaLength, nil
}

func (p *MPEG4AudioPacket) handleSingleHeader(header mpeg4AUHeader, data []byte) ([]byte, error) {
	if header.size == 0 {
		return nil, fmt.Errorf("%w: AU-size 0", errMPEG4SizeMismatch)
	}

	if header.size == len(data) {
		return p.completeAU(data)
	}

	if p.Mode == MPEG4ModeAACLBR {
		return nil, errMPEG4Fragmentation
	}

	if err := validateFragmentHeader(header, len(data)); err != nil {
		return nil, err
	}

	if !p.Fragmented {
		return p.startFragment(header, data)
	}

	return p.continueFragment(header, data)
}

func validateFragmentHeader(header mpeg4AUHeader, dataLen int) error {
	if header.size < dataLen {
		return fmt.Errorf(
			"%w: fragment of %d octets exceeds AU-size %d",
			errMPEG4SizeMismatch, dataLen, header.size,
		)
	}

	if header.size > aachbrMaxAUSize {
		return fmt.Errorf(
			"%w: AU-size %d exceeds the AAC-hbr limit of %d octets",
			errMPEG4SizeMismatch, header.size, aachbrMaxAUSize,
		)
	}

	return nil
}

func (p *MPEG4AudioPacket) completeAU(data []byte) ([]byte, error) {
	// Any in-progress fragmented AU must have been lost.
	if p.Fragmented {
		p.resetFragment()

		return nil, errMPEG4MissingFragment
	}

	au := cloneBytes(data)
	p.AUs = [][]byte{au}
	p.head = true
	p.tail = true

	return au, nil
}

func (p *MPEG4AudioPacket) startFragment(header mpeg4AUHeader, data []byte) ([]byte, error) {
	// header.size > len(data) by construction here: an equal size was the
	// complete-AU case, and a smaller size was already rejected.
	p.Fragmented = true
	p.expectedAUSize = header.size
	p.fragmentBuffer = append(p.fragmentBuffer[:0], data...)
	p.head = true
	p.tail = false

	return []byte{}, nil
}

func (p *MPEG4AudioPacket) continueFragment(header mpeg4AUHeader, data []byte) ([]byte, error) {
	if header.size != p.expectedAUSize {
		p.resetFragment()

		return nil, fmt.Errorf(
			"%w: fragment names AU-size %d but %d was being reassembled",
			errMPEG4SizeMismatch, header.size, p.expectedAUSize,
		)
	}

	p.fragmentBuffer = append(p.fragmentBuffer, data...)
	p.head = false

	if len(p.fragmentBuffer) > p.expectedAUSize {
		p.resetFragment()

		return nil, fmt.Errorf("%w: reassembled data exceeds AU-size", errMPEG4SizeMismatch)
	}

	if len(p.fragmentBuffer) < p.expectedAUSize {
		p.tail = false

		return []byte{}, nil
	}

	au := cloneBytes(p.fragmentBuffer)
	p.resetFragment()
	p.AUs = [][]byte{au}
	p.tail = true

	return au, nil
}

func (p *MPEG4AudioPacket) handleMultipleHeaders(
	headers []mpeg4AUHeader,
	data []byte,
) ([]byte, error) {
	if p.Fragmented {
		// A complete-AU packet arrived before the fragmented AU was finished.
		p.resetFragment()

		return nil, errMPEG4MissingFragment
	}

	aus := make([][]byte, 0, len(headers))
	offset := 0

	for i, header := range headers {
		if header.size == 0 || offset+header.size > len(data) {
			return nil, fmt.Errorf(
				"%w: header %d declares %d octets, %d available",
				errMPEG4SizeMismatch, i, header.size, len(data)-offset,
			)
		}

		aus = append(aus, cloneBytes(data[offset:offset+header.size]))
		offset += header.size
	}

	if offset != len(data) {
		return nil, fmt.Errorf(
			"%w: %d trailing octets after all access units",
			errMPEG4SizeMismatch, len(data)-offset,
		)
	}

	p.AUs = aus
	p.head = true
	p.tail = true

	out := make([]byte, 0, len(data))
	for _, au := range aus {
		out = append(out, au...)
	}

	return out, nil
}

func (p *MPEG4AudioPacket) resetFragment() {
	p.Fragmented = false
	p.fragmentBuffer = p.fragmentBuffer[:0]
	p.expectedAUSize = 0
}

// MPEG4RTPInfo carries the RTP header fields a MPEG4AudioPacket needs in
// addition to the payload. It keeps the codecs package free of an import of the
// parent rtp package, which itself imports codecs.
type MPEG4RTPInfo struct {
	SequenceNumber uint16
	Timestamp      uint32
	Marker         bool
	Payload        []byte
}

// UnmarshalRTP parses an RTP packet described by info. In addition to the
// payload parsing done by Unmarshal it validates sequencing and timing:
//   - a backwards sequence number returns errMPEG4OutOfOrder,
//   - a timestamp change while a fragmented AU is pending, or a positive step
//     smaller than ConstantDuration, returns errMPEG4TimestampJump and drops the
//     incomplete AU,
//   - the marker bit must be set on the final fragment/complete-AU packets and
//     clear on continuation fragments, otherwise errMPEG4BadMarker is returned.
func (p *MPEG4AudioPacket) UnmarshalRTP(info MPEG4RTPInfo) ([]byte, error) {
	if info.Payload == nil {
		return nil, errMPEG4NilPacket
	}

	if err := p.checkRTPState(info.SequenceNumber, info.Timestamp); err != nil {
		return nil, err
	}

	out, err := p.Unmarshal(info.Payload)
	if err != nil {
		return nil, err
	}

	if err := p.checkMarker(info.Marker); err != nil {
		return nil, err
	}

	return out, nil
}

func (p *MPEG4AudioPacket) checkRTPState(seq uint16, timestamp uint32) error {
	if p.hasLastSeq {
		// Modular uint16 subtraction: a difference at or above half the sequence
		// number space means seq is older than the last packet.
		if delta := seq - p.lastSeq; delta >= mpeg4SeqBackwardsThreshold {
			return fmt.Errorf("%w: got %d after %d", errMPEG4OutOfOrder, seq, p.lastSeq)
		}
	}

	p.hasLastSeq = true
	p.lastSeq = seq

	if p.hasTimestamp {
		step := timestamp - p.lastTimestamp
		if p.Fragmented && timestamp != p.lastTimestamp {
			p.resetFragment()

			return fmt.Errorf(
				"%w: %d -> %d while a fragmented access unit was pending",
				errMPEG4TimestampJump, p.lastTimestamp, timestamp,
			)
		}

		if p.ConstantDuration != 0 && step > 0 && step < p.ConstantDuration {
			return fmt.Errorf(
				"%w: step %d is smaller than the configured constant duration %d",
				errMPEG4TimestampJump, step, p.ConstantDuration,
			)
		}
	}

	p.hasTimestamp = true
	p.lastTimestamp = timestamp

	return nil
}

func (p *MPEG4AudioPacket) checkMarker(marker bool) error {
	// A packet is a tail exactly when it completed an AU (or carried complete AUs).
	if marker != p.tail {
		return fmt.Errorf("%w: marker=%t but tail=%t", errMPEG4BadMarker, marker, p.tail)
	}

	return nil
}

// IsPartitionHead reports whether the last parsed packet starts an access unit:
// true for complete-AU packets and first fragments, false for continuation
// fragments.
func (p *MPEG4AudioPacket) IsPartitionHead(_ []byte) bool {
	return p.head
}

// IsPartitionTail reports whether the last parsed packet completes an access
// unit. It mirrors the RTP marker semantics of RFC 3640: false on continuation
// fragments, true on the final fragment and on complete-AU packets.
func (p *MPEG4AudioPacket) IsPartitionTail(marker bool, _ []byte) bool {
	if p.tail {
		return true
	}

	return marker && !p.Fragmented
}

// bitReader reads unsigned values from an MSB-first bit stream.
type bitReader struct {
	data []byte
	pos  int
}

func newBitReader(data []byte) *bitReader {
	return &bitReader{data: data}
}

func (r *bitReader) read(width int) (int, error) {
	if width == 0 {
		return 0, nil
	}

	if r.pos+width > len(r.data)*8 {
		return 0, errMPEG4Truncated
	}

	value := 0
	for range width {
		byteIndex := r.pos / 8
		bit := (r.data[byteIndex] >> (7 - r.pos%8)) & 1
		value = (value << 1) | int(bit)
		r.pos++
	}

	return value, nil
}

// skipPadding consumes width bits and requires them all to be zero.
func (r *bitReader) skipPadding(width int) error {
	padding, err := r.read(width)
	if err != nil || padding != 0 {
		return fmt.Errorf("%w: non-zero or truncated AU-header padding", errMPEG4Truncated)
	}

	return nil
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	return out
}
