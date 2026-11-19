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

	// JPEG (RFC 2435) Errors.
	errJPEGShortPacket          = errors.New("JPEG packet is not large enough")
	errJPEGInvalidType          = errors.New("JPEG type is not supported by RFC 2435")
	errJPEGInvalidQ             = errors.New("JPEG Q field is reserved or otherwise invalid")
	errJPEGInvalidDimension     = errors.New("JPEG dimensions must be a non-zero multiple of 8 and at most 2040")
	errJPEGQuantLength          = errors.New("JPEG quantization table header length exceeds remaining payload")
	errJPEGQuantTable           = errors.New("JPEG quantization table is missing, duplicated or uses 16-bit precision")
	errJPEGHeaderMismatch       = errors.New("JPEG fragment header fields differ from the frame head")
	errJPEGDuplicateFragment    = errors.New("JPEG fragment offset has already been received")
	errJPEGOverlappingFragment  = errors.New("JPEG fragment overlaps a previously received fragment")
	errJPEGOffsetTooLarge       = errors.New("JPEG fragment offset plus payload length exceeds 2^24 bytes")
	errJPEGRestartMissing       = errors.New("JPEG restart type requires a restart marker header")
	errJPEGRestartIntervalZero  = errors.New("JPEG restart interval MUST NOT be zero")
	errJPEGMissingSOI           = errors.New("JPEG payload must start with a SOI marker")
	errJPEGTruncatedSegment     = errors.New("JPEG marker segment is truncated")
	errJPEGUnsupportedMode      = errors.New("only baseline sequential JPEG (SOF0) is supported")
	errJPEGUnsupportedSampling  = errors.New("only 4:2:2 (type 0) and 4:2:0 (type 1) sampling is supported")
	errJPEGUnsupportedPrecision = errors.New("only 8-bit JPEG samples are supported")
	errJPEGNonStandardHuffman   = errors.New("RFC 2435 requires the standard Annex K.3 Huffman tables")
	errJPEGInvalidScan          = errors.New("JPEG scan header is not a valid 3-component baseline scan")
	errJPEGRestartMarkerOutside = errors.New("JPEG restart markers may only appear on MCU boundaries")
	errJPEGMarkerInScan         = errors.New("unexpected JPEG marker inside entropy-coded scan data")
	errJPEGMissingQuantization  = errors.New("JPEG frame does not define quantization tables")
	errJPEGIncompleteFrame      = errors.New("JPEG frame fragments are missing")
)
