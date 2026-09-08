package usage

import (
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
