#!/usr/bin/env node

const provider = process.argv[2];
if (!['openai', 'anthropic'].includes(provider)) {
  console.error('usage: node runner.mjs openai|anthropic');
  process.exit(2);
}

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`qualification: ${name} is required`);
  return value;
};

const baseURL = required('GRIPLINE_SDK_BASE_URL');
const apiKey = required('GRIPLINE_SDK_API_KEY');
const model = required('GRIPLINE_SDK_MODEL');
const scenario = process.env.GRIPLINE_SDK_SCENARIO || '';
const wireModel = scenario ? `${model}-${scenario}` : model;
const stream = process.env.GRIPLINE_SDK_STREAM === '1';
const expectUsage = process.env.GRIPLINE_SDK_EXPECT_USAGE !== '0';
const timeout = Number.parseInt(process.env.GRIPLINE_SDK_MAX_SECONDS || '30', 10) * 1000;

const numericUsage = (usage) => Object.fromEntries(
  Object.entries(usage || {}).filter(([, value]) => Number.isFinite(value)),
);
const usageOrFail = (usage) => {
  const result = numericUsage(usage);
  if (Object.keys(result).length === 0 && expectUsage) throw new Error('provider response did not include usage');
  const expectedRaw = process.env.GRIPLINE_SDK_EXPECT_USAGE_JSON;
  if (expectedRaw) {
    const expected = JSON.parse(expectedRaw);
    for (const [key, value] of Object.entries(expected)) {
      if (result[key] !== value) throw new Error(`usage mismatch for ${key}: got ${result[key]}, want ${value}`);
    }
  }
  return result;
};

const content = scenario === 'large'
  ? `qualification large input ${'x'.repeat(65536)}`
  : 'qualification ping';
const openAITools = [{
  type: 'function',
  function: {
    name: 'lookup',
    description: 'qualification tool',
    parameters: { type: 'object', properties: { ok: { type: 'boolean' } } },
  },
}];
const anthropicTools = [{
  name: 'lookup',
  description: 'qualification tool',
  input_schema: { type: 'object', properties: { ok: { type: 'boolean' } } },
}];

const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), timeout);

try {
  let result;
  if (provider === 'openai') {
    const { default: OpenAI } = await import('openai');
    const client = new OpenAI({
      apiKey,
      baseURL,
      maxRetries: scenario === 'retry' ? 1 : 0,
      timeout,
      fetchOptions: { signal: controller.signal },
    });
    const callOnce = async () => {
      const request = {
        model: wireModel,
        messages: [{ role: 'user', content }],
        stream,
        ...(scenario === 'tool' ? { tools: openAITools } : {}),
        ...(stream ? { stream_options: { include_usage: true } } : {}),
      };
      if (stream) {
        let chunks = 0;
        let usage;
        for await (const chunk of await client.chat.completions.create(request)) {
          chunks += 1;
          usage ||= chunk.usage;
        }
        return { chunks, usage: usageOrFail(usage) };
      }
      const response = await client.chat.completions.create(request);
      if (scenario === 'tool' && !response.choices[0].message.tool_calls?.length) {
        throw new Error('OpenAI tool scenario did not return a tool call');
      }
      return { usage: usageOrFail(response.usage) };
    };
    const parallel = Number.parseInt(process.env.GRIPLINE_SDK_PARALLEL || '0', 10);
    const requests = Number.parseInt(process.env.GRIPLINE_SDK_REQUESTS || '1', 10);
    const results = parallel
      ? await Promise.all(Array.from({ length: parallel }, () => callOnce()))
      : await (async () => { const out = []; for (let i = 0; i < requests; i += 1) out.push(await callOnce()); return out; })();
    result = { provider, stream, requests: results.length, usage: results[0].usage };
  } else {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const client = new Anthropic({
      apiKey,
      baseURL: process.env.GRIPLINE_SDK_ANTHROPIC_BASE_URL || baseURL,
      maxRetries: scenario === 'retry' ? 1 : 0,
      timeout,
      fetchOptions: { signal: controller.signal },
    });
    const callOnce = async () => {
      const request = {
        model: wireModel,
        max_tokens: Number.parseInt(process.env.GRIPLINE_SDK_MAX_TOKENS || '64', 10),
        messages: [{ role: 'user', content }],
        stream,
        ...(scenario === 'tool' ? { tools: anthropicTools } : {}),
      };
      if (stream) {
        let events = 0;
        const usage = {};
        for await (const event of await client.messages.create(request)) {
          events += 1;
          Object.assign(usage, numericUsage(event.usage));
          if (event.type === 'message_start') Object.assign(usage, numericUsage(event.message?.usage));
        }
        return { events, usage: usageOrFail(usage) };
      }
      const response = await client.messages.create(request);
      if (scenario === 'tool' && !response.content.some((item) => item.type === 'tool_use')) {
        throw new Error('Anthropic tool scenario did not return a tool use');
      }
      return { usage: usageOrFail(response.usage) };
    };
    const parallel = Number.parseInt(process.env.GRIPLINE_SDK_PARALLEL || '0', 10);
    const requests = Number.parseInt(process.env.GRIPLINE_SDK_REQUESTS || '1', 10);
    const results = parallel
      ? await Promise.all(Array.from({ length: parallel }, () => callOnce()))
      : await (async () => { const out = []; for (let i = 0; i < requests; i += 1) out.push(await callOnce()); return out; })();
    result = { provider, stream, requests: results.length, usage: results[0].usage };
  }
  console.log(JSON.stringify(result));
} finally {
  clearTimeout(timer);
}
