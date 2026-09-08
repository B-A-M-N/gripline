// Package usage contains the small, provider-facing usage-metering contract.
//
// A provider integration can implement this package without importing any
// Gripline internal package. The gateway reserves the estimate before the
// backend request and settles it with usage observed from the bounded response
// metadata parser.
package usage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
	// MaxBodyBytes is the gateway's enforced body ceiling. Adapters use it
	// when BodySize is unknown so chunked requests reserve conservatively.
	MaxBodyBytes int64
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
	// MaxOutputTokens is the hard, conservative output reservation. When set,
	// client-provided metadata may not lower it before execution.
	MaxOutputTokens int64
	// InputBytesPerToken is a conservative upper-bound divisor. The default
	// is one byte/token, not a language-token average.
	InputBytesPerToken int64
	MaxEstimatedTokens int64
}

// NewJSONProvider constructs a bounded provider adapter. The request input
// estimate is body bytes divided by InputBytesPerToken (default one), while a
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
		InputBytesPerToken:  1,
		MaxEstimatedTokens:  1 << 31,
	}, nil
}

func (p *JSONProvider) Estimate(obs Observation) Estimate {
	if p == nil {
		return Estimate{Requests: 1}
	}
	input := int64(0)
	bodySize := obs.BodySize
	if bodySize < 0 {
		bodySize = obs.MaxBodyBytes
	}
	if bodySize > 0 {
		div := p.InputBytesPerToken
		if div <= 0 {
			div = 1
		}
		input = (bodySize + div - 1) / div
	}
	output := p.DefaultOutputTokens
	if p.MaxOutputTokens > 0 {
		output = p.MaxOutputTokens
	} else {
		for _, name := range []string{"X-Gripline-Max-Output-Tokens", "X-Max-Tokens", "Max-Tokens"} {
			if raw := strings.TrimSpace(obs.Header.Get(name)); raw != "" {
				if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n >= 0 {
					output = n
					break
				}
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
	provider     *JSONProvider
	estimate     Estimate
	input        int64
	output       int64
	combined     int64
	inputSeen    bool
	outputSeen   bool
	combinedSeen bool
	seen         bool
	carry        []byte
	overflow     bool
}

const usageCarryBytes = 64 << 10

type usageRecord struct {
	input, output, combined             int64
	inputSeen, outputSeen, combinedSeen bool
}

func (s *jsonSession) ObserveChunk(chunk []byte) {
	if s == nil || len(chunk) == 0 {
		return
	}
	if len(s.carry)+len(chunk) > usageCarryBytes {
		s.carry = nil
		s.overflow = true
		return
	}
	s.carry = append(s.carry, chunk...)
	for {
		if i := bytes.IndexByte(s.carry, '\n'); i >= 0 {
			s.processRecord(s.carry[:i])
			s.carry = append(s.carry[:0], s.carry[i+1:]...)
			continue
		}
		if rec, ok := parseUsageRecord(s.carry, s.provider.Format); ok {
			s.merge(rec)
			s.carry = nil
		} else if bytes.Equal(bytes.TrimSpace(s.carry), []byte("data: [DONE]")) {
			s.carry = nil
		}
		break
	}
}

func (s *jsonSession) processRecord(record []byte) {
	record = bytes.TrimSpace(record)
	if len(record) == 0 || bytes.Equal(record, []byte("data: [DONE]")) {
		return
	}
	if rec, ok := parseUsageRecord(record, s.provider.Format); ok {
		s.merge(rec)
	}
}

func (s *jsonSession) merge(rec usageRecord) {
	if rec.inputSeen && (!s.inputSeen || rec.input > s.input) {
		s.input = rec.input
	}
	if rec.outputSeen && (!s.outputSeen || rec.output > s.output) {
		s.output = rec.output
	}
	if rec.combinedSeen && (!s.combinedSeen || rec.combined > s.combined) {
		s.combined = rec.combined
	}
	s.inputSeen = s.inputSeen || rec.inputSeen
	s.outputSeen = s.outputSeen || rec.outputSeen
	s.combinedSeen = s.combinedSeen || rec.combinedSeen
	s.seen = s.seen || rec.inputSeen || rec.outputSeen || rec.combinedSeen
}

func (s *jsonSession) Finish(_ error) Estimate {
	if s == nil {
		return Estimate{Requests: 1}
	}
	if !s.seen || s.overflow || !s.inputSeen || !s.outputSeen {
		// Missing, malformed, or partial usage never settles below the
		// admission estimate. Observed fields can only increase an unobserved
		// dimension, so telemetry cannot turn a request into free usage.
		actual := s.estimate
		if s.inputSeen && s.input > actual.InputTokens {
			actual.InputTokens = s.input
		}
		if s.outputSeen && s.output > actual.OutputTokens {
			actual.OutputTokens = s.output
		}
		actual.CombinedTokens = safeAdd(actual.InputTokens, actual.OutputTokens)
		if s.combinedSeen && s.combined > actual.CombinedTokens {
			actual.CombinedTokens = s.combined
		}
		actual.InputTokens = s.provider.clamp(actual.InputTokens)
		actual.OutputTokens = s.provider.clamp(actual.OutputTokens)
		actual.CombinedTokens = s.provider.clamp(actual.CombinedTokens)
		return s.provider.withCost(actual)
	}
	actual := Estimate{Requests: 1, InputTokens: s.input, OutputTokens: s.output, CombinedTokens: s.combined}
	if actual.CombinedTokens < safeAdd(actual.InputTokens, actual.OutputTokens) {
		actual.CombinedTokens = safeAdd(actual.InputTokens, actual.OutputTokens)
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

// parseUsageRecord accepts only a complete top-level provider usage envelope.
// It never searches arbitrary strings, so model-generated content containing
// token-looking keys cannot control accounting.
func parseUsageRecord(record []byte, format Format) (usageRecord, bool) {
	record = bytes.TrimSpace(record)
	if bytes.HasPrefix(record, []byte("data:")) {
		record = bytes.TrimSpace(record[len("data:"):])
	}
	if len(record) == 0 || bytes.Equal(record, []byte("[DONE]")) {
		return usageRecord{}, false
	}
	top, err := decodeUniqueObject(record)
	if err != nil {
		return usageRecord{}, false
	}
	raw, ok := top["usage"]
	if !ok && format == FormatAnthropic {
		// message_start places input usage inside the provider's message
		// envelope; message_delta places it at top level. Accept only this
		// documented path, never an arbitrary recursive search.
		if messageRaw, messageOK := top["message"]; messageOK {
			if message, messageErr := decodeUniqueObject(messageRaw); messageErr == nil {
				raw, ok = message["usage"]
			}
		}
	}
	if !ok {
		return usageRecord{}, false
	}
	usage, err := decodeUniqueObject(raw)
	if err != nil {
		return usageRecord{}, false
	}
	var out usageRecord
	switch format {
	case FormatOpenAI:
		out.input, out.inputSeen = nonNegativeInt(usage["prompt_tokens"])
		out.output, out.outputSeen = nonNegativeInt(usage["completion_tokens"])
	case FormatAnthropic:
		out.input, out.inputSeen = nonNegativeInt(usage["input_tokens"])
		out.output, out.outputSeen = nonNegativeInt(usage["output_tokens"])
	default:
		return usageRecord{}, false
	}
	out.combined, out.combinedSeen = nonNegativeInt(usage["total_tokens"])
	return out, out.inputSeen || out.outputSeen || out.combinedSeen
}

// decodeUniqueObject is intentionally limited to the small provider envelope
// objects. encoding/json maps otherwise accept duplicate keys with last-value
// wins, which would make an attacker-controlled malformed usage record
// ambiguous. Duplicate keys are rejected and the session falls back to its
// conservative admission estimate.
func decodeUniqueObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("usage: provider envelope must be an object")
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("usage: provider object key is not a string")
		}
		if _, exists := out[key]; exists {
			return nil, errors.New("usage: duplicate provider object key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("usage: provider envelope contains trailing JSON")
		}
		return nil, err
	}
	return out, nil
}

func nonNegativeInt(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil || n < 0 {
		return 0, false
	}
	return n, true
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
