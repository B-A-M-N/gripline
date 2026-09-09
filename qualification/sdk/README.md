# Provider SDK qualification

These runners exercise the gateway with the vendor clients rather than with a
generic HTTP client. They are intentionally opt-in because they need a
provider-compatible backend, a disposable bearer, and network access to the
qualification deployment.

Both runners cover non-streaming and streaming calls and require the response
to expose the expected provider usage dimensions when
`GRIPLINE_SDK_EXPECT_USAGE=1` (the default). The shell harness runs each
provider in its endpoint-specific Gripline metering profile and verifies the
settled usage counters and cost total. It also runs provider-shaped tool calls,
a large request body, retry-after-429, deliberate 5xx, client cancellation,
same-client connection reuse, and parallel requests. Set
`GRIPLINE_SDK_STREAM=1` for the streaming case. `GRIPLINE_SDK_MAX_SECONDS`
provides a client-side cancellation bound; it is useful for the cancellation
case and prevents a hung provider from turning into an unbounded qualification
run.

Common environment:

```text
GRIPLINE_SDK_BASE_URL=https://gateway.example/v1
GRIPLINE_SDK_ANTHROPIC_BASE_URL=https://gateway.example
GRIPLINE_SDK_API_KEY=<disposable gateway credential>
GRIPLINE_SDK_MODEL=<provider model accepted by the backend>
GRIPLINE_SDK_PROFILE=chat|responses|embeddings|models|messages
GRIPLINE_SDK_STREAM=0|1
GRIPLINE_SDK_EXPECT_USAGE=1
GRIPLINE_SDK_MAX_SECONDS=30
GRIPLINE_SDK_SCENARIO=tool|large|retry|server-error|cancel|connection|parallel
GRIPLINE_SDK_REQUESTS=4          # same-client sequential reuse
GRIPLINE_SDK_PARALLEL=4          # same-client concurrent calls
```

Run the Python client with the exact versions pinned in the qualification
manifest installed first:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r qualification/sdk/python/requirements.lock
python qualification/sdk/python/runner.py openai
python qualification/sdk/python/runner.py anthropic
```

Run the TypeScript client with the exact versions pinned in `package.json`:

```sh
cd qualification/sdk/typescript
npm ci --ignore-scripts
node runner.mjs openai
node runner.mjs anthropic
```

The repository does not commit provider API keys or claim that a local fake
backend is provider-behavior evidence. A release record must retain the pinned
SDK versions, provider/model, stream mode, retry policy, cancellation result,
and the authoritative usage/cost comparison for each case.
