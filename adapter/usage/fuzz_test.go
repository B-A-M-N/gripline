package usage

import "testing"

func FuzzJSONProviderUsage(f *testing.F) {
	f.Add([]byte(`data: {"usage":{"prompt_tokens":1,"completion_tokens":2}}`))
	f.Add([]byte(`data: {"usage":{"input_tokens":1,"output_tokens":2}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range []Format{FormatOpenAI, FormatAnthropic} {
			provider, err := NewJSONProvider(format, Pricing{InputMicrounitsPerToken: 2, OutputMicrounitsPerToken: 3}, 16)
			if err != nil {
				t.Fatal(err)
			}
			session := provider.Begin(Observation{BodySize: -1, MaxBodyBytes: 1 << 20}, nil)
			session.ObserveChunk(data)
			_ = session.Finish(nil)
		}
	})
}
