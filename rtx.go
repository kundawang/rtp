// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// rtxPayloadLen is the length in bytes of the Original Sequence Number (OSN)
// field that prefixes every retransmission payload, as defined in RFC 4588.
const rtxPayloadLen = 2

// Sentinel errors returned by the RTX encapsulator and decapsulator.
var (
	// ErrRTXMappingNotFound is returned when a packet's SSRC/payload type does
	// not match any configured original/RTX mapping.
	ErrRTXMappingNotFound = errors.New("RTX mapping not found for SSRC and payload type")

	// ErrRTXPacketNotRetransmitted is returned when a retransmission is
	// requested for a sequence number that was never stored or has been evicted
	// from the retransmission cache.
	ErrRTXPacketNotRetransmitted = errors.New("RTP packet is not available for retransmission")

	// ErrRTXEmptyPayload is returned when an RTX operation is attempted on a
	// packet without a payload: an RTX packet always carries at least the
	// 2-byte Original Sequence Number field.
	ErrRTXEmptyPayload = errors.New("RTX packet payload must not be empty")

	// ErrRTXInvalidMapping is returned when a mapping is configured with
	// identical original and RTX payload types or SSRCs, or with duplicated
	// entries.
	ErrRTXInvalidMapping = errors.New("invalid RTX mapping")

	// ErrRTXInvalidConfig is returned when an RTX component is constructed
	// without mappings or with a non-positive cache size.
	ErrRTXInvalidConfig = errors.New("invalid RTX configuration")
)

// RTXMapping describes the relationship between an original RTP stream and its
// RTX retransmission stream, as negotiated in the SDP "apt" attribute and
// defined in RFC 4588.
type RTXMapping struct {
	// OriginalPayloadType is the payload type of the original ("associated")
	// RTP stream.
	OriginalPayloadType uint8

	// RTXPayloadType is the payload type used on the retransmission stream.
	RTXPayloadType uint8

	// OriginalSSRC is the SSRC of the original RTP stream.
	OriginalSSRC uint32

	// RTXSSRC is the SSRC used on the retransmission stream.
	RTXSSRC uint32
}

// Validate checks that the mapping uses distinct payload types and SSRCs for
// the original and retransmission streams.
func (m RTXMapping) Validate() error {
	if m.OriginalPayloadType == m.RTXPayloadType {
		return fmt.Errorf("%w: original and RTX payload type are both %d",
			ErrRTXInvalidMapping, m.OriginalPayloadType)
	}

	if m.OriginalSSRC == m.RTXSSRC {
		return fmt.Errorf("%w: original and RTX SSRC are both %d",
			ErrRTXInvalidMapping, m.OriginalSSRC)
	}

	return nil
}

// RTXEncapsulator turns original RTP packets into RFC 4588 retransmission
// packets. It owns an independent RTX sequence number space and a bounded cache
// of original packets so that lost packets can be retransmitted on request.
//
// RTXEncapsulator is not safe for concurrent use.
type RTXEncapsulator struct {
	mapping     RTXMapping
	rtxSequence uint16

	// cache is a ring buffer indexed by insertion order. head is the next slot
	// to be written and stored is the number of slots currently holding
	// packets. Entries are matched by their original sequence number, so
	// sequence-number wraparound at 65535 needs no special handling.
	cache     []rtxCacheEntry
	head      uint16
	stored    uint16
	cacheSize uint16
}

// rtxCacheEntry is one slot of the retransmission ring cache.
type rtxCacheEntry struct {
	packet        Packet
	sequence      uint16
	retransmitted bool
	occupied      bool
}

// NewRTXEncapsulator creates an RTXEncapsulator for mapping. initialSequence is
// the first value of the independent RTX sequence number space (the first
// encapsulated packet uses initialSequence, the next initialSequence+1, and so
// on, wrapping at 65535). cacheSize bounds the number of original packets kept
// for retransmission; when the cache is full the oldest packet is evicted.
func NewRTXEncapsulator(mapping RTXMapping, initialSequence uint16, cacheSize int) (*RTXEncapsulator, error) {
	if err := mapping.Validate(); err != nil {
		return nil, err
	}

	if cacheSize <= 0 || cacheSize > 1<<16-1 {
		return nil, fmt.Errorf("%w: cache size must be between 1 and 65535", ErrRTXInvalidConfig)
	}

	return &RTXEncapsulator{
		mapping:     mapping,
		rtxSequence: initialSequence,
		cache:       make([]rtxCacheEntry, cacheSize),
		cacheSize:   uint16(cacheSize), // nolint:gosec // G115 bounds are checked above
	}, nil
}

// Encapsulate wraps an original packet in an RTX packet. The original packet is
// not modified: the returned packet has its own RTX payload type, SSRC and
// sequence number, keeps the original timestamp, marker bit, CSRCs and header
// extensions, and prefixes the original payload with the 2-byte Original
// Sequence Number (OSN) field.
func (e *RTXEncapsulator) Encapsulate(original *Packet) (*Packet, error) {
	if original == nil {
		return nil, fmt.Errorf("%w: packet is nil", ErrRTXEmptyPayload)
	}

	if original.PayloadType != e.mapping.OriginalPayloadType || original.SSRC != e.mapping.OriginalSSRC {
		return nil, fmt.Errorf("%w: SSRC %d payload type %d",
			ErrRTXMappingNotFound, original.SSRC, original.PayloadType)
	}

	if len(original.Payload) == 0 {
		return nil, ErrRTXEmptyPayload
	}

	rtx := original.Clone()

	// RFC 4588 section 2.1: the retransmission packet keeps the timestamp,
	// marker bit, CSRC list and header extensions of the original packet, but
	// uses the RTX payload type, SSRC and an independent sequence number.
	rtx.PayloadType = e.mapping.RTXPayloadType
	rtx.SSRC = e.mapping.RTXSSRC
	rtx.SequenceNumber = e.rtxSequence
	e.rtxSequence++

	// Padding belongs to the original packet; the RTX payload is rebuilt from
	// the unpadded original payload plus the OSN field.
	rtx.Padding = false
	rtx.PaddingSize = 0
	rtx.Header.PaddingSize = 0

	rtxPayload := make([]byte, rtxPayloadLen+len(original.Payload))
	binary.BigEndian.PutUint16(rtxPayload, original.SequenceNumber)
	copy(rtxPayload[rtxPayloadLen:], original.Payload)
	rtx.Payload = rtxPayload

	return rtx, nil
}

// Store keeps a copy of an original packet in the retransmission cache so that
// it can later be served by Retransmit. Packets must be stored in sequence
// number order. When the bounded cache is full the oldest packet is evicted.
func (e *RTXEncapsulator) Store(packet *Packet) error {
	if packet == nil {
		return fmt.Errorf("%w: packet is nil", ErrRTXEmptyPayload)
	}

	if packet.PayloadType != e.mapping.OriginalPayloadType || packet.SSRC != e.mapping.OriginalSSRC {
		return fmt.Errorf("%w: SSRC %d payload type %d",
			ErrRTXMappingNotFound, packet.SSRC, packet.PayloadType)
	}

	slot := e.head
	if !e.cache[slot].occupied {
		e.stored++
	}

	e.cache[slot] = rtxCacheEntry{
		packet:   *packet.Clone(),
		sequence: packet.SequenceNumber,
		occupied: true,
	}

	e.head = (e.head + 1) % e.cacheSize

	return nil
}

// Retransmit encapsulates the cached original packet with originalSequence.
// The returned RTX packet consumes a fresh RTX sequence number. duplicated is
// true when this sequence number has already been retransmitted once; a request
// for a sequence number that was never stored or has been evicted returns
// ErrRTXPacketNotRetransmitted.
func (e *RTXEncapsulator) Retransmit(originalSequence uint16) (rtxPacket *Packet, duplicated bool, err error) {
	entry, err := e.lookup(originalSequence)
	if err != nil {
		return nil, false, err
	}

	duplicated = entry.retransmitted
	entry.retransmitted = true

	packet := entry.packet
	rtxPacket, err = e.Encapsulate(&packet)
	if err != nil {
		return nil, false, err
	}

	return rtxPacket, duplicated, nil
}

// lookup returns the cache entry for originalSequence. The cache is bounded by
// configuration (typically a few hundred packets), so a direct scan keeps the
// result independent of any assumption about gaps or wraparound in the original
// sequence number space. A sequence number that was never stored or has been
// evicted returns ErrRTXPacketNotRetransmitted.
func (e *RTXEncapsulator) lookup(originalSequence uint16) (*rtxCacheEntry, error) {
	for i := range e.cache {
		entry := &e.cache[i]
		if entry.occupied && entry.sequence == originalSequence {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("%w: sequence number %d", ErrRTXPacketNotRetransmitted, originalSequence)
}

// RTXDecapsulator restores original RTP packets from RFC 4588 retransmission
// packets according to the configured original/RTX mappings.
//
// RTXDecapsulator is not safe for concurrent use.
type RTXDecapsulator struct {
	mappings []RTXMapping
}

// NewRTXDecapsulator creates an RTXDecapsulator holding one mapping per
// retransmission stream it is expected to receive.
func NewRTXDecapsulator(mappings ...RTXMapping) (*RTXDecapsulator, error) {
	if len(mappings) == 0 {
		return nil, fmt.Errorf("%w: at least one mapping is required", ErrRTXInvalidConfig)
	}

	seen := make(map[RTXMapping]struct{}, len(mappings))

	for _, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return nil, err
		}

		if _, ok := seen[mapping]; ok {
			return nil, fmt.Errorf("%w: duplicated mapping for payload type %d",
				ErrRTXInvalidMapping, mapping.RTXPayloadType)
		}

		seen[mapping] = struct{}{}
	}

	return &RTXDecapsulator{mappings: mappings}, nil
}

// Decapsulate recovers the original packet from an RTX packet: it reads the
// Original Sequence Number from the first two payload bytes, restores the
// original payload type, SSRC and sequence number, and leaves the timestamp,
// marker bit, CSRCs and header extensions untouched. The input packet is not
// modified.
func (d *RTXDecapsulator) Decapsulate(rtxPacket *Packet) (*Packet, error) {
	if rtxPacket == nil {
		return nil, fmt.Errorf("%w: packet is nil", ErrRTXMappingNotFound)
	}

	mapping, err := d.findMapping(rtxPacket)
	if err != nil {
		return nil, err
	}

	if len(rtxPacket.Payload) < rtxPayloadLen {
		return nil, fmt.Errorf("%w: payload of %d byte(s) is shorter than the %d-byte OSN field",
			ErrRTXEmptyPayload, len(rtxPacket.Payload), rtxPayloadLen)
	}

	original := rtxPacket.Clone()
	original.PayloadType = mapping.OriginalPayloadType
	original.SSRC = mapping.OriginalSSRC
	original.SequenceNumber = binary.BigEndian.Uint16(rtxPacket.Payload[:rtxPayloadLen])

	original.Padding = false
	original.PaddingSize = 0
	original.Header.PaddingSize = 0

	payload := make([]byte, len(rtxPacket.Payload)-rtxPayloadLen)
	copy(payload, rtxPacket.Payload[rtxPayloadLen:])
	original.Payload = payload

	return original, nil
}

// findMapping returns the configuration matching the RTX packet's SSRC and
// payload type.
func (d *RTXDecapsulator) findMapping(packet *Packet) (RTXMapping, error) {
	for _, mapping := range d.mappings {
		if packet.SSRC == mapping.RTXSSRC && packet.PayloadType == mapping.RTXPayloadType {
			return mapping, nil
		}
	}

	return RTXMapping{}, fmt.Errorf("%w: SSRC %d payload type %d",
		ErrRTXMappingNotFound, packet.SSRC, packet.PayloadType)
}
