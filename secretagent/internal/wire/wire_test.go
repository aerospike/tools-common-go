package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func frame(magic uint32, size int, body string) []byte {
	msg := make([]byte, HeaderSize, HeaderSize+len(body))
	binary.BigEndian.PutUint32(msg[:4], magic)
	binary.BigEndian.PutUint32(msg[4:], uint32(size)) //nolint:gosec // test sizes fit in uint32

	return append(msg, body...)
}

func TestEncode(t *testing.T) {
	t.Parallel()

	msg, err := encode(Request{Resource: "res", SecretKey: "key"})
	require.NoError(t, err)

	body := `{"Resource":"res","SecretKey":"key"}`
	require.Equal(t, frame(Magic, len(body), body), msg)
}

func TestEncodeOmitsEmptyResource(t *testing.T) {
	t.Parallel()

	msg, err := encode(Request{SecretKey: "key"})
	require.NoError(t, err)
	require.Equal(t, `{"SecretKey":"key"}`, string(msg[HeaderSize:]))
}

func TestEncodeTooLarge(t *testing.T) {
	t.Parallel()

	_, err := encode(Request{SecretKey: strings.Repeat("k", MaxMessageSize)})
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	want := Response{SecretValue: "value"}
	require.NoError(t, Write(&buf, want))

	var got Response
	require.NoError(t, Read(&buf, &got))
	require.Equal(t, want, got)
	require.Zero(t, buf.Len())
}

func TestRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        []byte
		wantErr      error
		wantProtocol bool
	}{
		{
			name:         "invalid magic",
			input:        frame(0xdeadbeef, 2, "{}"),
			wantProtocol: true,
		},
		{
			name:         "body over limit",
			input:        frame(Magic, MaxMessageSize+1, ""),
			wantProtocol: true,
		},
		{
			name:         "malformed json",
			input:        frame(Magic, 15, `{"SecretValue":`),
			wantProtocol: true,
		},
		{
			name:    "no data",
			input:   nil,
			wantErr: io.EOF,
		},
		{
			name:    "short header",
			input:   []byte{0x51, 0xde},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "short body",
			input:   frame(Magic, 10, "{}"),
			wantErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var res Response

			err := Read(bytes.NewReader(tt.input), &res)
			require.Error(t, err)
			require.Equal(t, tt.wantProtocol, errors.Is(err, ErrProtocol), err)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestReadErrorOmitsBody(t *testing.T) {
	t.Parallel()

	body := `{"SecretValue":"hunter2`

	var res Response

	err := Read(bytes.NewReader(frame(Magic, len(body), body)), &res)
	require.ErrorIs(t, err, ErrProtocol)
	require.NotContains(t, err.Error(), "hunter2")
}
