package codecs

import (
	"bytes"
	"image/jpeg"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJPEG_RTPPacketizerIntegration drives the payloader through the real RTP
// Packetizer and reassembles using the marker bit, as a camera receiver would.
func TestJPEG_RTPPacketizerIntegration(t *testing.T) {
	_, chroma := makeJPEGStaticTables(75)
	img := makeTestYCbCr(48, 32, false)
	frame := encodeJPEGTestFrame(img, true, customJPEGLumaQuant, chroma, 2)

	packetizer := rtp.NewPacketizer(200, 26, 1234, &JPEGPayloader{},
		rtp.NewRandomSequencer(), 90000)

	packets := packetizer.Packetize(frame, 90000/30)
	require.NotEmpty(t, packets)

	depacketizer := &JPEGPacket{}
	var assembled []byte
	for _, pkt := range packets {
		assert.Equal(t, pkt.Marker,
			depacketizer.IsDetectedFinalPacketInSequence(pkt.Marker))
		assert.Equal(t, uint8(26), pkt.PayloadType)
		assert.LessOrEqual(t, len(pkt.Payload), 200-12)

		_, err := depacketizer.Unmarshal(pkt.Payload)
		require.NoError(t, err)
		if pkt.Marker {
			depacketizer.MarkFrameEnd()
			assembled, err = depacketizer.Flush()
			require.NoError(t, err)
		}
	}
	require.NotEmpty(t, assembled)

	decoded, err := jpeg.Decode(bytes.NewReader(assembled))
	require.NoError(t, err)
	assert.Equal(t, 48, decoded.Bounds().Dx())
	assert.Equal(t, 32, decoded.Bounds().Dy())

	// A second frame resets and reassembles independently.
	packets2 := packetizer.Packetize(frame, 90000/30)
	dep2 := &JPEGPacket{}
	for _, pkt := range packets2[:len(packets2)-1] {
		_, err = dep2.Unmarshal(pkt.Payload)
		require.NoError(t, err)
	}
	// Flushing before the marked final packet reports an incomplete frame.
	_, err = dep2.Flush()
	assert.ErrorIs(t, err, errJPEGIncompleteFrame)
}
