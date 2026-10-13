package secretagent

import "errors"

// Every error returned by this package wraps exactly one of these sentinels.
var (
	// ErrInvalidConfig reports a Config, TLSOptions or secret reference that
	// cannot be used.
	ErrInvalidConfig = errors.New("invalid secret agent configuration")
	// ErrUnsupported reports a valid but unsupported option combination, such
	// as TLS over a unix socket.
	ErrUnsupported = errors.New("unsupported secret agent option")
	// ErrRequestFailed reports that the agent could not be reached, the exchange
	// with it failed or timed out, or the agent answered with an error.
	ErrRequestFailed = errors.New("secret agent request failed")
	// ErrInvalidResponse reports a response that breaks the agent protocol or
	// holds an unusable secret value.
	ErrInvalidResponse = errors.New("invalid secret agent response")
)
