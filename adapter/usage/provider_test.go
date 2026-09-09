package usage

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestJSONProviderParsesBoundedOpenAIUsage(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{InputMicrounitsPerToken: 2, OutputMicrounitsPerToken: 3}, 64)
	if err != nil {
		t.Fatal(err)
	}
	p.InputBytesPerToken = 4
	obs := Observation{Header: http.Header{"X-Gripline-Max-Output-Tokens": []string{"12"}}, BodySize: 40}
	if got := p.Estimate(obs); got.InputTokens != 10 || got.OutputTokens != 12 || got.CostMicrounits != 56 {
		t.Fatalf("estimate=%+v", got)
	}
	s := p.Begin(obs, nil)
	s.ObserveChunk([]byte(`data: {"usage":{"prompt_tokens":7,"completion_tokens":11,"total_tokens":18}}`))
	got := s.Finish(nil)
	if got.InputTokens != 7 || got.OutputTokens != 11 || got.CombinedTokens != 18 || got.CostMicrounits != 47 {
		t.Fatalf("actual=%+v", got)
	}
}

func TestJSONProviderRecognizesSplitAnthropicFieldWithoutBuffering(t *testing.T) {
	p, err := NewJSONProvider(FormatAnthropic, Pricing{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{}, nil)
	prefix := strings.Repeat(" ", usageCarryBytes-100)
	s.ObserveChunk([]byte(prefix + `data: {"usage":{"input_to`))
	s.ObserveChunk([]byte(`kens":4,"output_tokens":9}}`))
	got := s.Finish(nil)
	if got.InputTokens != 4 || got.OutputTokens != 9 || got.CombinedTokens != 13 {
		t.Fatalf("actual=%+v", got)
	}
	js, ok := s.(*jsonSession)
	if !ok {
		t.Fatal("provider returned unexpected session type")
	}
	if len(js.carry) > usageCarryBytes {
		t.Fatalf("usage carry grew to %d", len(js.carry))
	}
}

func TestJSONProviderIgnoresTokenLookingModelContent(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	obs := Observation{BodySize: -1, MaxBodyBytes: 100}
	s := p.Begin(obs, nil)
	s.ObserveChunk([]byte(`{"choices":[{"message":{"content":"\\\"total_tokens\\\":1 \\"output_tokens\\\":999999999"}}]}`))
	got := s.Finish(nil)
	if got.InputTokens != 100 || got.OutputTokens != 8 || got.CombinedTokens != 108 {
		t.Fatalf("model content changed conservative estimate: %+v", got)
	}
}

func TestJSONProviderParsesOnlyStructuredUsageAndMergesSSE(t *testing.T) {
	p, err := NewJSONProvider(FormatAnthropic, Pricing{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{BodySize: 4}, nil)
	s.ObserveChunk([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\n"))
	s.ObserveChunk([]byte("data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n"))
	got := s.Finish(nil)
	if got.InputTokens != 7 || got.OutputTokens != 9 || got.CombinedTokens != 16 {
		t.Fatalf("structured SSE usage=%+v", got)
	}
}

func TestJSONProviderRejectsDuplicateUsageKeys(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{BodySize: 10}, nil)
	s.ObserveChunk([]byte(`{"usage":{"prompt_tokens":7,"prompt_tokens":100,"completion_tokens":9}}`))
	got := s.Finish(nil)
	if got.InputTokens != 10 || got.OutputTokens != 4 || got.CombinedTokens != 14 {
		t.Fatalf("duplicate usage field must use conservative fallback, got %+v", got)
	}
}

func TestJSONProviderReservesConfiguredMaximumOutput(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	p.MaxOutputTokens = 20
	got := p.Estimate(Observation{Header: http.Header{"X-Max-Tokens": []string{"1"}}, BodySize: 10})
	if got.OutputTokens != 20 {
		t.Fatalf("client metadata lowered hard output reservation: %+v", got)
	}
}

func TestJSONProviderRejectsNegativeAndOverflowUsage(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{BodySize: 10}, nil)
	s.ObserveChunk([]byte(`{"usage":{"prompt_tokens":-1,"completion_tokens":999999999999999999999}}`))
	got := s.Finish(nil)
	if got.InputTokens != 10 || got.OutputTokens != 4 || got.CombinedTokens != 14 {
		t.Fatalf("invalid usage must fall back conservatively: %+v", got)
	}
}

func TestJSONProviderUsesEndpointSpecificOpenAIProfiles(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{InputMicrounitsPerToken: 2, OutputMicrounitsPerToken: 3}, 8)
	if err != nil {
		t.Fatal(err)
	}

	responses := p.Begin(Observation{URLPath: "/v1/responses", BodySize: 4}, nil)
	responses.ObserveChunk([]byte(`{"usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}`))
	if got := responses.Finish(nil); got.InputTokens != 4 || got.OutputTokens != 6 || got.CombinedTokens != 10 {
		t.Fatalf("responses usage=%+v", got)
	}

	stream := p.Begin(Observation{URLPath: "/v1/responses", BodySize: 4}, nil)
	stream.ObserveChunk([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"fake usage\"}\n"))
	stream.ObserveChunk([]byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":7,\"total_tokens\":12}}}\n"))
	if got := stream.Finish(nil); got.InputTokens != 5 || got.OutputTokens != 7 || got.CombinedTokens != 12 {
		t.Fatalf("streaming responses usage=%+v", got)
	}

	embeddings := p.Begin(Observation{URLPath: "/v1/embeddings", BodySize: 12}, nil)
	embeddings.ObserveChunk([]byte(`{"usage":{"prompt_tokens":5,"total_tokens":5}}`))
	if got := embeddings.Finish(nil); got.InputTokens != 5 || got.OutputTokens != 0 || got.CombinedTokens != 5 {
		t.Fatalf("embeddings usage=%+v", got)
	}

	models := p.Begin(Observation{URLPath: "/v1/models", BodySize: 100}, nil)
	models.ObserveChunk([]byte(`{"data":[{"id":"model","content":"usage"}]}`))
	if got := models.Finish(nil); got.Requests != 1 || got.InputTokens != 0 || got.OutputTokens != 0 || got.CombinedTokens != 0 || got.CostMicrounits != 0 {
		t.Fatalf("models usage=%+v", got)
	}
}

func TestJSONProviderChargesAnthropicCacheDimensions(t *testing.T) {
	p, err := NewJSONProvider(FormatAnthropic, Pricing{
		InputMicrounitsPerToken: 2, OutputMicrounitsPerToken: 3,
		CacheReadMicrounitsPerToken: 5, CacheCreationMicrounitsPerToken: 7,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{URLPath: "/v1/messages", BodySize: 10}, nil)
	s.ObserveChunk([]byte(`data: {"type":"message_start","message":{"usage":{"input_tokens":10,"cache_read_input_tokens":4,"cache_creation_input_tokens":3}}}` + "\n"))
	s.ObserveChunk([]byte(`data: {"type":"message_delta","usage":{"input_tokens":10,"output_tokens":2,"cache_read_input_tokens":4,"cache_creation_input_tokens":3}}` + "\n"))
	got := s.Finish(nil)
	if got.InputTokens != 17 || got.OutputTokens != 2 || got.CombinedTokens != 19 || got.CacheReadInputTokens != 4 || got.CacheCreationInputTokens != 3 || got.CostMicrounits != 67 {
		t.Fatalf("cached Anthropic usage=%+v", got)
	}
}

func TestJSONProviderIncompleteAnthropicSettlementIncludesCacheInput(t *testing.T) {
	p, err := NewJSONProvider(FormatAnthropic, Pricing{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{Method: "POST", URLPath: "/v1/messages", BodySize: 10}, nil)
	s.ObserveChunk([]byte(`data: {"type":"message_start","message":{"usage":{"input_tokens":10,"cache_read_input_tokens":4,"cache_creation_input_tokens":3}}}` + "\n"))
	got := s.Finish(io.ErrUnexpectedEOF)
	if got.InputTokens != 17 || got.CacheReadInputTokens != 4 || got.CacheCreationInputTokens != 3 || got.CombinedTokens != 25 {
		t.Fatalf("incomplete Anthropic usage dropped cache dimensions: %+v", got)
	}
}

func TestJSONProviderAnthropicCacheCreationSubtypes(t *testing.T) {
	p, err := NewJSONProvider(FormatAnthropic, Pricing{
		InputMicrounitsPerToken: 2, OutputMicrounitsPerToken: 3,
		CacheReadMicrounitsPerToken:       5,
		CacheCreation5mMicrounitsPerToken: 7, CacheCreation1hMicrounitsPerToken: 11,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{URLPath: "/v1/messages", BodySize: 10}, nil)
	s.ObserveChunk([]byte(`{"usage":{"input_tokens":10,"output_tokens":2,"cache_read_input_tokens":4,"cache_creation":{"ephemeral_5m_input_tokens":3,"ephemeral_1h_input_tokens":5}}}`))
	got := s.Finish(nil)
	if got.InputTokens != 22 || got.CacheCreation5mInputTokens != 3 || got.CacheCreation1hInputTokens != 5 || got.CostMicrounits != 122 {
		t.Fatalf("Anthropic cache subtype usage=%+v", got)
	}
}

func TestJSONProviderRejectsPartialEndpointUsage(t *testing.T) {
	p, err := NewJSONProvider(FormatOpenAI, Pricing{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Begin(Observation{URLPath: "/v1/responses", BodySize: 10}, nil)
	s.ObserveChunk([]byte(`{"usage":{"input_tokens":2,"output_tokens":3}}`))
	got := s.Finish(nil)
	if got.InputTokens != 10 || got.OutputTokens != 4 || got.CombinedTokens != 14 {
		t.Fatalf("partial Responses usage must use conservative estimate: %+v", got)
	}
}
