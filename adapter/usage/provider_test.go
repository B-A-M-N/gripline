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
	s.ObserveChunk([]byte(strings.Repeat("x", usageCarryBytes-2) + `"input_to`))
	s.ObserveChunk([]byte(`kens":4,"output_tokens":9}`))
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
