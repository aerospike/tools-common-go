// Package wire implements the Aerospike Secret Agent message framing: an
// 8-byte header (magic, then big-endian body length) followed by a JSON body.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Magic          = 0x51dec1cc
	HeaderSize     = 8
	MaxMessageSize = 1 << 20
)

// ErrProtocol reports a message that does not follow the Secret Agent framing.
var ErrProtocol = errors.New("secret agent protocol violation")

// ErrTooLarge reports an outgoing message body above MaxMessageSize.
var ErrTooLarge = errors.New("secret agent message too large")

type Request struct {
	Resource  string `json:"Resource,omitempty"`
	SecretKey string `json:"SecretKey"`
}

type Response struct {
	SecretValue string `json:"SecretValue,omitempty"`
	Error       string `json:"Error,omitempty"`
}

// encode returns v as one framed message.
func encode(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	if len(body) > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, len(body), MaxMessageSize)
	}

	msg := make([]byte, HeaderSize, HeaderSize+len(body))
	binary.BigEndian.PutUint32(msg[:4], Magic)
	binary.BigEndian.PutUint32(msg[4:], uint32(len(body))) //nolint:gosec // bounded by MaxMessageSize above

	return append(msg, body...), nil
}

// Write encodes v and writes it to w as one framed message.
func Write(w io.Writer, v any) error {
	msg, err := encode(v)
	if err != nil {
		return err
	}

	_, err = w.Write(msg)

	return err
}

// Read reads one framed message from r into v. Transport failures are returned
// as is; framing and decoding failures wrap ErrProtocol. Decoding errors never
// include the body, because a response body can hold a secret.
func Read(r io.Reader, v any) error {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	if magic := binary.BigEndian.Uint32(header[:4]); magic != Magic {
		return fmt.Errorf("%w: invalid magic number %#x", ErrProtocol, magic)
	}

	size := binary.BigEndian.Uint32(header[4:])
	if size > MaxMessageSize {
		return fmt.Errorf("%w: body of %d bytes exceeds limit of %d", ErrProtocol, size, MaxMessageSize)
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	return decode(body, v)
}

// decode unmarshals one message body into v.
func decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: malformed JSON body", ErrProtocol)
	}

	return nil
}
