// Package usage contains the small, provider-facing usage-metering contract.
//
// A provider integration can implement this package without importing any
// Gripline internal package. The gateway reserves the estimate before the
// backend request and settles it with usage observed from the bounded response
// metadata parser.
package usage

import (
	"bytes"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// Observation is the credential-free request view supplied to an adapter.
// BodySize is a transport-level size only; the body itself is never exposed.
type Observation struct {
	Header     http.Header
	RemoteAddr string
	ProtoMajor int
	URLPath    string
	BodySize   int64
}

// Estimate is the usage shape known to the gateway before or after execution.
// Cost is integer micro-units of the provider currency.
type Estimate struct {
	Requests       int64
	InputTokens    int64
	OutputTokens   int64
	CombinedTokens int64
	CostMicrounits int64
}

// Session observes bounded response chunks and returns settled usage exactly
// once at end-of-stream. Implementations must not retain response content.
type Session interface {
	ObserveChunk([]byte)
	Finish(error) Estimate
}

// Provider is the provider-facing metering contract.
type Provider interface {
	Estimate(Observation) Estimate
	Begin(Observation, *http.Response) Session
}

// Format selects the response usage envelope convention.
type Format string

const (
	FormatOpenAI    Format = "openai"
	FormatAnthropic Format = "anthropic"
)

// Pricing is expressed in micro-units per token. Zero pricing is valid when a
// provider wants token enforcement without cost enforcement.
type Pricing struct {
	InputMicrounitsPerToken  int64
	OutputMicrounitsPerToken int64
}

// JSONProvider is a bounded adapter for the usage fields emitted by OpenAI- or
// Anthropic-compatible JSON/SSE APIs. It scans only a small carry window plus
// the current chunk; prompt/completion content is never accumulated.
type JSONProvider struct {
	Format              Format
	Pricing             Pricing
	DefaultOutputTokens int64
	InputBytesPerToken  int64
	MaxEstimatedTokens  int64
}

// NewJSONProvider constructs a bounded provider adapter. The request input
// estimate is body bytes divided by InputBytesPerToken (default four), while a
// configured output-token header or DefaultOutputTokens supplies the
// pre-execution output reservation.
func NewJSONProvider(format Format, pricing Pricing, defaultOutputTokens int64) (*JSONProvider, error) {
	if format != FormatOpenAI && format != FormatAnthropic {
		return nil, errors.New("usage: format must be openai or anthropic")
	}
	if pricing.InputMicrounitsPerToken < 0 || pricing.OutputMicrounitsPerToken < 0 {
		return nil, errors.New("usage: pricing must be non-negative")
	}
	if defaultOutputTokens < 0 {
		return nil, errors.New("usage: default output tokens must be non-negative")
	}
	return &JSONProvider{
		Format:              format,
		Pricing:             pricing,
		DefaultOutputTokens: defaultOutputTokens,
		InputBytesPerToken:  4,
		MaxEstimatedTokens:  1 << 31,
	}, nil
}

func (p *JSONProvider) Estimate(obs Observation) Estimate {
	if p == nil {
		return Estimate{Requests: 1}
	}
	input := int64(0)
	if obs.BodySize > 0 {
		div := p.InputBytesPerToken
		if div <= 0 {
			div = 4
		}
		input = (obs.BodySize + div - 1) / div
	}
	output := p.DefaultOutputTokens
	for _, name := range []string{"X-Gripline-Max-Output-Tokens", "X-Max-Tokens", "Max-Tokens"} {
		if raw := strings.TrimSpace(obs.Header.Get(name)); raw != "" {
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n >= 0 {
				output = n
				break
			}
		}
	}
	input, output = p.clamp(input), p.clamp(output)
	return p.withCost(Estimate{Requests: 1, InputTokens: input, OutputTokens: output, CombinedTokens: safeAdd(input, output)})
}

func (p *JSONProvider) Begin(obs Observation, _ *http.Response) Session {
	return &jsonSession{provider: p, estimate: p.Estimate(obs)}
}

type jsonSession struct {
	provider *JSONProvider
	estimate Estimate
	input    int64
	output   int64
	combined int64
	seen     bool
	carry    []byte
}

const usageCarryBytes = 256

func (s *jsonSession) ObserveChunk(chunk []byte) {
	if s == nil || len(chunk) == 0 {
		return
	}
	// The carry is only long enough to recognize a field split at a chunk
	// boundary. It is not a response buffer.
	window := make([]byte, len(s.carry)+len(chunk))
	copy(window, s.carry)
	copy(window[len(s.carry):], chunk)
	if n, ok := lastIntField(window, "prompt_tokens"); ok {
		s.input, s.seen = n, true
	}
	if n, ok := lastIntField(window, "input_tokens"); ok {
		s.input, s.seen = n, true
	}
	if n, ok := lastIntField(window, "completion_tokens"); ok {
		s.output, s.seen = n, true
	}
	if n, ok := lastIntField(window, "output_tokens"); ok {
		s.output, s.seen = n, true
	}
	if n, ok := lastIntField(window, "total_tokens"); ok {
		s.combined, s.seen = n, true
	}
	if len(window) > usageCarryBytes {
		window = window[len(window)-usageCarryBytes:]
	}
	s.carry = append(s.carry[:0], window...)
}

func (s *jsonSession) Finish(_ error) Estimate {
	if s == nil {
		return Estimate{Requests: 1}
	}
	actual := Estimate{Requests: 1, InputTokens: s.input, OutputTokens: s.output, CombinedTokens: s.combined}
	if actual.CombinedTokens == 0 {
		actual.CombinedTokens = safeAdd(actual.InputTokens, actual.OutputTokens)
	}
	if !s.seen {
		// A provider that omitted usage still settles the bounded estimate. This
		// preserves request accounting and avoids treating missing telemetry as
		// free usage.
		actual = s.estimate
	}
	actual.InputTokens = s.provider.clamp(actual.InputTokens)
	actual.OutputTokens = s.provider.clamp(actual.OutputTokens)
	actual.CombinedTokens = s.provider.clamp(actual.CombinedTokens)
	return s.provider.withCost(actual)
}

func (p *JSONProvider) clamp(n int64) int64 {
	if n < 0 {
		return 0
	}
	max := p.MaxEstimatedTokens
	if max > 0 && n > max {
		return max
	}
	return n
}

func (p *JSONProvider) withCost(e Estimate) Estimate {
	e.CostMicrounits = safeMulAdd(e.InputTokens, p.Pricing.InputMicrounitsPerToken,
		e.OutputTokens, p.Pricing.OutputMicrounitsPerToken)
	return e
}

// lastIntField extracts the last bounded integer for a JSON field name. It is
// intentionally a small lexical parser: it accepts JSON/SSE envelopes and
// refuses non-decimal or overflowing values rather than guessing.
func lastIntField(data []byte, field string) (int64, bool) {
	needle := []byte(`"` + field + `"`)
	var value int64
	found := false
	for from := 0; ; {
		i := bytes.Index(data[from:], needle)
		if i < 0 {
			break
		}
		i += from + len(needle)
		for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n' || data[i] == ':') {
			i++
		}
		start := i
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
		if i > start {
			if n, err := strconv.ParseInt(string(data[start:i]), 10, 64); err == nil {
				value, found = n, true
			}
		}
		from = i
		if from <= start {
			from = start + 1
		}
		if from >= len(data) {
			break
		}
	}
	return value, found
}

func safeAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func safeMulAdd(a, b, c, d int64) int64 {
	if a <= 0 || b <= 0 {
		a, b = 0, 0
	}
	if c <= 0 || d <= 0 {
		c, d = 0, 0
	}
	left, right := int64(0), int64(0)
	if b != 0 && a > math.MaxInt64/b {
		left = math.MaxInt64
	} else {
		left = a * b
	}
	if d != 0 && c > math.MaxInt64/d {
		right = math.MaxInt64
	} else {
		right = c * d
	}
	return safeAdd(left, right)
}
