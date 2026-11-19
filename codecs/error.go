// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "errors"

var (
	errShortPacket          = errors.New("packet is not large enough")
	errNilPacket            = errors.New("invalid nil packet")
	errTooManyPDiff         = errors.New("too many PDiff")
	errTooManySpatialLayers = errors.New("too many spatial layers")
	errUnhandledNALUType    = errors.New("NALU Type is unhandled")

	// AV1 Errors.
	errIsKeyframeAndFragment = errors.New(
		"bits Z and N are set. Not possible to have OBU be tail fragment and be keyframe",
	)

	// MPEG4-generic (RFC 3640) errors.
	errMPEG4NilPacket       = errors.New("MPEG4-generic: invalid nil packet")
	errMPEG4ShortPacket     = errors.New("MPEG4-generic: packet is not large enough")
	errMPEG4BadMode         = errors.New("MPEG4-generic: unsupported mode, only AAC-lbr and AAC-hbr are supported")
	errMPEG4BadConfig       = errors.New("MPEG4-generic: configured bit widths do not match the mode")
	errMPEG4AUTooLarge      = errors.New("MPEG4-generic: access unit is too large for its size field or the MTU")
	errMPEG4Truncated       = errors.New("MPEG4-generic: bit field or data section is truncated")
	errMPEG4IllegalIndex    = errors.New("MPEG4-generic: illegal AU-Index, the first AU-Index must be coded 0")
	errMPEG4SizeMismatch    = errors.New("MPEG4-generic: AU-size does not match the data section length")
	errMPEG4MissingFragment = errors.New("MPEG4-generic: fragmented access unit is incomplete, a fragment is missing")
	errMPEG4OutOfOrder      = errors.New("MPEG4-generic: RTP sequence number went backwards")
	errMPEG4TimestampJump   = errors.New("MPEG4-generic: timestamp changed while a fragmented access unit was pending")
	errMPEG4Fragmentation   = errors.New("MPEG4-generic: fragmentation is forbidden in AAC-lbr mode")
	errMPEG4BadMarker       = errors.New("MPEG4-generic: marker bit is inconsistent with the packet contents")
)
