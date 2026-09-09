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
	Method     string
	URLPath    string
	BodySize   int64
	// UsageProfile is an explicit route-level schema selection. When empty,
	// the adapter retains its provider/path compatibility defaults.
	UsageProfile UsageProfile
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
	// CacheReadInputTokens and CacheCreationInputTokens preserve Anthropic's
	// separately priced input dimensions. InputTokens remains the total input
	// dimension used for quota accounting.
	CacheReadInputTokens       int64
	CacheCreationInputTokens   int64
	CacheCreation5mInputTokens int64
	CacheCreation1hInputTokens int64
	// CostConservative is true when the provider did not expose enough cache
	// detail to price the record exactly.
	CostConservative bool
	CostMicrounits   int64
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

// UsageProfile selects the exact provider usage envelope for one endpoint.
// Provider-compatible APIs do not share one universal token schema: OpenAI
// chat/completions, Responses, embeddings, and models each have distinct
// semantics, as does Anthropic Messages.
type UsageProfile string

const (
	ProfileNone              UsageProfile = "none"
	ProfileOpenAIChat        UsageProfile = "openai-chat"
	ProfileOpenAIResponses   UsageProfile = "openai-responses"
	ProfileOpenAIEmbeddings  UsageProfile = "openai-embeddings"
	ProfileOpenAIModels      UsageProfile = "openai-models"
	ProfileAnthropicMessages UsageProfile = "anthropic-messages"
)

// Pricing is expressed in micro-units per token. Zero pricing is valid when a
// provider wants token enforcement without cost enforcement.
type Pricing struct {
	InputMicrounitsPerToken           int64
	OutputMicrounitsPerToken          int64
	CacheReadMicrounitsPerToken       int64
	CacheCreationMicrounitsPerToken   int64
	CacheCreation5mMicrounitsPerToken int64
	CacheCreation1hMicrounitsPerToken int64
}

// CostMode controls whether the adapter emits provider cost estimates.
type CostMode string

const (
	CostModeConservative CostMode = "conservative"
	CostModeExact        CostMode = "exact"
	CostModeNone         CostMode = "none"
)

// JSONProvider is a bounded adapter for the usage fields emitted by OpenAI- or
// Anthropic-compatible JSON/SSE APIs. It scans only a small carry window plus
// the current chunk; prompt/completion content is never accumulated.
type JSONProvider struct {
	Format              Format
	Pricing             Pricing
	CostMode            CostMode
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
	if pricing.InputMicrounitsPerToken < 0 || pricing.OutputMicrounitsPerToken < 0 ||
		pricing.CacheReadMicrounitsPerToken < 0 || pricing.CacheCreationMicrounitsPerToken < 0 ||
		pricing.CacheCreation5mMicrounitsPerToken < 0 || pricing.CacheCreation1hMicrounitsPerToken < 0 {
		return nil, errors.New("usage: pricing must be non-negative")
	}
	if defaultOutputTokens < 0 {
		return nil, errors.New("usage: default output tokens must be non-negative")
	}
	return &JSONProvider{
		Format:  format,
		Pricing: pricing,
		// Direct users historically received exact settlement pricing while
		// admission remains conservative via withCost(..., true). Deployments
		// should set this explicitly when they want conservative settlement.
		CostMode:            CostModeExact,
		DefaultOutputTokens: defaultOutputTokens,
		InputBytesPerToken:  1,
		MaxEstimatedTokens:  1 << 31,
	}, nil
}

func (p *JSONProvider) Estimate(obs Observation) Estimate {
	if p == nil {
		return Estimate{Requests: 1}
	}
	return p.estimate(obs, profileFor(p.Format, obs.Method, obs.URLPath, obs.UsageProfile))
}

func (p *JSONProvider) estimate(obs Observation, profile UsageProfile) Estimate {
	if profile == ProfileNone || profile == ProfileOpenAIModels {
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
	output := int64(0)
	if profile != ProfileOpenAIEmbeddings {
		output = p.DefaultOutputTokens
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
	}
	input, output = p.clamp(input), p.clamp(output)
	return p.withCost(Estimate{Requests: 1, InputTokens: input, OutputTokens: output, CombinedTokens: safeAdd(input, output)}, profile, true)
}

func (p *JSONProvider) Begin(obs Observation, _ *http.Response) Session {
	profile := profileFor(p.Format, obs.Method, obs.URLPath, obs.UsageProfile)
	if profile == ProfileNone {
		return requestOnlySession{}
	}
	return &jsonSession{provider: p, profile: profile, estimate: p.estimate(obs, profile), knownZero: profile == ProfileOpenAIModels}
}

type requestOnlySession struct{}

func (requestOnlySession) ObserveChunk([]byte)   {}
func (requestOnlySession) Finish(error) Estimate { return Estimate{Requests: 1} }

type jsonSession struct {
	provider          *JSONProvider
	profile           UsageProfile
	estimate          Estimate
	input             int64
	output            int64
	combined          int64
	cacheRead         int64
	cacheCreate       int64
	cacheCreate5m     int64
	cacheCreate1h     int64
	inputSeen         bool
	outputSeen        bool
	combinedSeen      bool
	cacheReadSeen     bool
	cacheCreateSeen   bool
	cacheCreate5mSeen bool
	cacheCreate1hSeen bool
	seen              bool
	knownZero         bool
	carry             []byte
	overflow          bool
}

const usageCarryBytes = 64 << 10

type usageRecord struct {
	input, output, combined              int64
	cacheRead, cacheCreate               int64
	cacheCreate5m, cacheCreate1h         int64
	inputSeen, outputSeen, combinedSeen  bool
	cacheReadSeen, cacheCreateSeen       bool
	cacheCreate5mSeen, cacheCreate1hSeen bool
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
		if rec, ok := parseUsageRecord(s.carry, s.profile); ok {
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
	if rec, ok := parseUsageRecord(record, s.profile); ok {
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
	if rec.cacheReadSeen && (!s.cacheReadSeen || rec.cacheRead > s.cacheRead) {
		s.cacheRead = rec.cacheRead
	}
	if rec.cacheCreateSeen && (!s.cacheCreateSeen || rec.cacheCreate > s.cacheCreate) {
		s.cacheCreate = rec.cacheCreate
	}
	if rec.cacheCreate5mSeen && (!s.cacheCreate5mSeen || rec.cacheCreate5m > s.cacheCreate5m) {
		s.cacheCreate5m = rec.cacheCreate5m
	}
	if rec.cacheCreate1hSeen && (!s.cacheCreate1hSeen || rec.cacheCreate1h > s.cacheCreate1h) {
		s.cacheCreate1h = rec.cacheCreate1h
	}
	s.inputSeen = s.inputSeen || rec.inputSeen
	s.outputSeen = s.outputSeen || rec.outputSeen
	s.combinedSeen = s.combinedSeen || rec.combinedSeen
	s.cacheReadSeen = s.cacheReadSeen || rec.cacheReadSeen
	s.cacheCreateSeen = s.cacheCreateSeen || rec.cacheCreateSeen
	s.cacheCreate5mSeen = s.cacheCreate5mSeen || rec.cacheCreate5mSeen
	s.cacheCreate1hSeen = s.cacheCreate1hSeen || rec.cacheCreate1hSeen
	s.seen = s.seen || rec.inputSeen || rec.outputSeen || rec.combinedSeen || rec.cacheReadSeen || rec.cacheCreateSeen || rec.cacheCreate5mSeen || rec.cacheCreate1hSeen
}

func (s *jsonSession) Finish(streamErr error) Estimate {
	if s == nil {
		return Estimate{Requests: 1}
	}
	if s.knownZero {
		return Estimate{Requests: 1}
	}
	complete := s.inputSeen && s.outputSeen
	switch s.profile {
	case ProfileOpenAIChat, ProfileOpenAIResponses, ProfileOpenAIEmbeddings:
		complete = complete && s.combinedSeen
	}
	if streamErr != nil || !s.seen || s.overflow || !complete {
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
		if s.profile == ProfileAnthropicMessages {
			// Cache dimensions are part of Anthropic input quota. Preserve them
			// even when a stream is interrupted; otherwise partial settlement
			// can under-charge a request that already consumed cached input.
			observedInput := s.input
			observedInput = safeAdd(observedInput, s.cacheRead)
			if s.cacheCreate5mSeen || s.cacheCreate1hSeen {
				observedInput = safeAdd(observedInput, safeAdd(s.cacheCreate5m, s.cacheCreate1h))
			} else {
				observedInput = safeAdd(observedInput, s.cacheCreate)
			}
			if observedInput > actual.InputTokens {
				actual.InputTokens = observedInput
			}
			if s.cacheReadSeen {
				actual.CacheReadInputTokens = s.cacheRead
			}
			if s.cacheCreateSeen {
				actual.CacheCreationInputTokens = s.cacheCreate
			}
			actual.CacheCreation5mInputTokens = s.cacheCreate5m
			actual.CacheCreation1hInputTokens = s.cacheCreate1h
			actual.CostConservative = s.cacheCreateSeen && !(s.cacheCreate5mSeen || s.cacheCreate1hSeen)
		}
		actual.CombinedTokens = safeAdd(actual.InputTokens, actual.OutputTokens)
		if s.combinedSeen && s.combined > actual.CombinedTokens {
			actual.CombinedTokens = s.combined
		}
		actual.InputTokens = s.provider.clamp(actual.InputTokens)
		actual.OutputTokens = s.provider.clamp(actual.OutputTokens)
		actual.CombinedTokens = s.provider.clamp(actual.CombinedTokens)
		return s.provider.withCost(actual, s.profile, false)
	}
	actualInput := s.input
	if s.profile == ProfileAnthropicMessages {
		actualInput = safeAdd(actualInput, s.cacheRead)
		if s.cacheCreate5mSeen || s.cacheCreate1hSeen {
			actualInput = safeAdd(actualInput, safeAdd(s.cacheCreate5m, s.cacheCreate1h))
		} else {
			actualInput = safeAdd(actualInput, s.cacheCreate)
		}
	}
	actual := Estimate{Requests: 1, InputTokens: actualInput, OutputTokens: s.output, CombinedTokens: s.combined,
		CacheReadInputTokens: s.cacheRead, CacheCreationInputTokens: s.cacheCreate,
		CacheCreation5mInputTokens: s.cacheCreate5m, CacheCreation1hInputTokens: s.cacheCreate1h,
		CostConservative: s.cacheCreateSeen && !(s.cacheCreate5mSeen || s.cacheCreate1hSeen)}
	if actual.CombinedTokens < safeAdd(actual.InputTokens, actual.OutputTokens) {
		actual.CombinedTokens = safeAdd(actual.InputTokens, actual.OutputTokens)
	}
	actual.InputTokens = s.provider.clamp(actual.InputTokens)
	actual.OutputTokens = s.provider.clamp(actual.OutputTokens)
	actual.CombinedTokens = s.provider.clamp(actual.CombinedTokens)
	return s.provider.withCost(actual, s.profile, false)
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

func (p *JSONProvider) withCost(e Estimate, profile UsageProfile, conservative bool) Estimate {
	if p.CostMode == CostModeNone {
		e.CostMicrounits = 0
		return e
	}
	conservative = conservative || e.CostConservative || p.CostMode == CostModeConservative
	inputRate := p.Pricing.InputMicrounitsPerToken
	if conservative {
		e.CostConservative = true
		// The estimate may contain total input tokens while the provider has not
		// exposed a trustworthy cache split. Price every input token at the
		// highest configured input/cache rate. This is conservative without
		// double-counting cache dimensions as both regular and cache input.
		inputRate = maxInt64(inputRate, p.Pricing.CacheReadMicrounitsPerToken)
		if profile == ProfileAnthropicMessages {
			inputRate = maxInt64(inputRate, p.cacheCreationRate(false))
			inputRate = maxInt64(inputRate, p.cacheCreationRate(true))
		}
		e.CostMicrounits = safeMulAdd(e.InputTokens, inputRate,
			e.OutputTokens, p.Pricing.OutputMicrounitsPerToken)
		return e
	}
	regularInput := e.InputTokens
	if profile == ProfileAnthropicMessages || e.CacheReadInputTokens > 0 || e.CacheCreationInputTokens > 0 || e.CacheCreation5mInputTokens > 0 || e.CacheCreation1hInputTokens > 0 {
		cacheTotal := safeAdd(e.CacheReadInputTokens, safeAdd(e.CacheCreation5mInputTokens, e.CacheCreation1hInputTokens))
		if e.CacheCreation5mInputTokens == 0 && e.CacheCreation1hInputTokens == 0 {
			cacheTotal = safeAdd(cacheTotal, e.CacheCreationInputTokens)
		}
		if regularInput >= cacheTotal {
			regularInput -= cacheTotal
		} else {
			regularInput = 0
		}
	}
	e.CostMicrounits = safeMulAdd(regularInput, inputRate,
		e.OutputTokens, p.Pricing.OutputMicrounitsPerToken)
	e.CostMicrounits = safeAdd(e.CostMicrounits,
		safeMulAdd(e.CacheReadInputTokens, p.Pricing.CacheReadMicrounitsPerToken,
			e.CacheCreation5mInputTokens, p.cacheCreationRate(false)))
	aggregateCreate := e.CacheCreationInputTokens
	if e.CacheCreation5mInputTokens != 0 || e.CacheCreation1hInputTokens != 0 {
		aggregateCreate = 0
	}
	e.CostMicrounits = safeAdd(e.CostMicrounits,
		safeMulAdd(e.CacheCreation1hInputTokens, p.cacheCreationRate(true),
			aggregateCreate, p.Pricing.CacheCreationMicrounitsPerToken))
	return e
}

func (p *JSONProvider) cacheCreationRate(hour bool) int64 {
	if hour && p.Pricing.CacheCreation1hMicrounitsPerToken != 0 {
		return p.Pricing.CacheCreation1hMicrounitsPerToken
	}
	if !hour && p.Pricing.CacheCreation5mMicrounitsPerToken != 0 {
		return p.Pricing.CacheCreation5mMicrounitsPerToken
	}
	return p.Pricing.CacheCreationMicrounitsPerToken
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func profileFor(format Format, method, path string, explicit UsageProfile) UsageProfile {
	if explicit != "" {
		return explicit
	}
	switch format {
	case FormatAnthropic:
		return ProfileAnthropicMessages
	case FormatOpenAI:
		switch path {
		case "/v1/responses":
			return ProfileOpenAIResponses
		case "/v1/embeddings":
			return ProfileOpenAIEmbeddings
		case "/v1/models":
			return ProfileOpenAIModels
		default:
			return ProfileOpenAIChat
		}
	default:
		return ProfileOpenAIChat
	}
}

// parseUsageRecord accepts only the exact documented provider usage path for
// the endpoint profile. It never recursively searches arbitrary JSON, so
// model-generated content containing token-looking keys cannot control
// accounting.
func parseUsageRecord(record []byte, profile UsageProfile) (usageRecord, bool) {
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
	raw, ok := usageObject(top, profile)
	if !ok {
		return usageRecord{}, false
	}
	usage := raw
	var out usageRecord
	switch profile {
	case ProfileOpenAIChat:
		out.input, out.inputSeen = requiredNonNegativeInt(usage, "prompt_tokens")
		out.output, out.outputSeen = requiredNonNegativeInt(usage, "completion_tokens")
		out.combined, out.combinedSeen = requiredNonNegativeInt(usage, "total_tokens")
		if cache, seen, ok := openAICacheRead(usage, "prompt_tokens_details"); !ok {
			return usageRecord{}, false
		} else if seen {
			out.cacheRead, out.cacheReadSeen = cache, true
		}
	case ProfileOpenAIResponses:
		out.input, out.inputSeen = requiredNonNegativeInt(usage, "input_tokens")
		out.output, out.outputSeen = requiredNonNegativeInt(usage, "output_tokens")
		out.combined, out.combinedSeen = requiredNonNegativeInt(usage, "total_tokens")
		if cache, seen, ok := openAICacheRead(usage, "input_tokens_details"); !ok {
			return usageRecord{}, false
		} else if seen {
			out.cacheRead, out.cacheReadSeen = cache, true
		}
	case ProfileOpenAIEmbeddings:
		out.input, out.inputSeen = requiredNonNegativeInt(usage, "prompt_tokens")
		out.combined, out.combinedSeen = requiredNonNegativeInt(usage, "total_tokens")
		// Embeddings have no completion dimension. Mark it seen only when the
		// complete embedding usage envelope was valid.
		out.outputSeen = out.inputSeen && out.combinedSeen
	case ProfileAnthropicMessages:
		out.input, out.inputSeen = requiredNonNegativeInt(usage, "input_tokens")
		out.output, out.outputSeen = requiredNonNegativeInt(usage, "output_tokens")
		if raw, exists := usage["cache_read_input_tokens"]; exists {
			out.cacheRead, out.cacheReadSeen = optionalNonNegativeInt(raw)
			if !out.cacheReadSeen {
				return usageRecord{}, false
			}
		}
		if raw, exists := usage["cache_creation_input_tokens"]; exists {
			out.cacheCreate, out.cacheCreateSeen = optionalNonNegativeInt(raw)
			if !out.cacheCreateSeen {
				return usageRecord{}, false
			}
		}
		if raw, exists := usage["cache_creation"]; exists {
			cache, err := decodeUniqueObject(raw)
			if err != nil {
				return usageRecord{}, false
			}
			if value, ok := cache["ephemeral_5m_input_tokens"]; ok {
				out.cacheCreate5m, out.cacheCreate5mSeen = optionalNonNegativeInt(value)
				if !out.cacheCreate5mSeen {
					return usageRecord{}, false
				}
			}
			if value, ok := cache["ephemeral_1h_input_tokens"]; ok {
				out.cacheCreate1h, out.cacheCreate1hSeen = optionalNonNegativeInt(value)
				if !out.cacheCreate1hSeen {
					return usageRecord{}, false
				}
			}
			if out.cacheCreate5mSeen || out.cacheCreate1hSeen {
				out.cacheCreate = safeAdd(out.cacheCreate5m, out.cacheCreate1h)
				out.cacheCreateSeen = true
			}
		}
		// Anthropic's message usage has no total_tokens field; the adapter
		// derives total input from the three documented input dimensions.
	default:
		return usageRecord{}, false
	}
	return out, out.inputSeen || out.outputSeen || out.combinedSeen || out.cacheReadSeen || out.cacheCreateSeen || out.cacheCreate5mSeen || out.cacheCreate1hSeen
}

// openAICacheRead parses the optional provider usage detail without treating
// arbitrary nested token-looking content as metering data. A missing detail
// object means zero cached tokens for this record; a malformed detail object
// invalidates the record and forces conservative settlement.
func openAICacheRead(usage map[string]json.RawMessage, detailsKey string) (int64, bool, bool) {
	raw, exists := usage[detailsKey]
	if !exists {
		return 0, false, true
	}
	details, err := decodeUniqueObject(raw)
	if err != nil {
		return 0, false, false
	}
	cached, exists := details["cached_tokens"]
	if !exists {
		return 0, false, true
	}
	value, ok := optionalNonNegativeInt(cached)
	if !ok {
		return 0, false, false
	}
	return value, true, true
}

func usageObject(top map[string]json.RawMessage, profile UsageProfile) (map[string]json.RawMessage, bool) {
	switch profile {
	case ProfileOpenAIResponses:
		if typ, ok := stringValue(top["type"]); ok && typ == "response.completed" {
			response, err := decodeUniqueObject(top["response"])
			if err != nil {
				return nil, false
			}
			usage, err := decodeUniqueObject(response["usage"])
			return usage, err == nil
		}
		// Non-streaming Responses returns usage at the response top level.
		usage, ok := top["usage"]
		if !ok {
			return nil, false
		}
		decoded, err := decodeUniqueObject(usage)
		return decoded, err == nil
	case ProfileAnthropicMessages:
		if typ, ok := stringValue(top["type"]); ok && typ == "message_start" {
			message, err := decodeUniqueObject(top["message"])
			if err != nil {
				return nil, false
			}
			usage, err := decodeUniqueObject(message["usage"])
			return usage, err == nil
		}
		// message_delta and non-streaming Messages use the top-level usage
		// member. No other nested path is accepted.
		usage, ok := top["usage"]
		if !ok {
			return nil, false
		}
		decoded, err := decodeUniqueObject(usage)
		return decoded, err == nil
	default:
		usage, ok := top["usage"]
		if !ok {
			return nil, false
		}
		decoded, err := decodeUniqueObject(usage)
		return decoded, err == nil
	}
}

func stringValue(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
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

func requiredNonNegativeInt(values map[string]json.RawMessage, key string) (int64, bool) {
	raw, ok := values[key]
	if !ok {
		return 0, false
	}
	return nonNegativeInt(raw)
}

func optionalNonNegativeInt(raw json.RawMessage) (int64, bool) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, true
	}
	return nonNegativeInt(raw)
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
