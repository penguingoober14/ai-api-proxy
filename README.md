# AI API Proxy (Deno Deploy)

A serverless proxy for Anthropic Claude and Google Gemini APIs, keeping your API keys secure.

## Why Use a Proxy?

**Problem**: Embedding API keys in mobile/web apps means anyone can extract them.

**Solution**: Keep keys on your server (this proxy), never in client code.

```
Before:  [App (has key)] → [AI API]           ❌ Key exposed
After:   [App (no key)]  → [Proxy (has key)] → [AI API]  ✅ Key secure
```

## Deployment (Deno Deploy)

### Option 1: Deploy via GitHub (Recommended)

1. Push this repo to GitHub
2. Go to [dash.deno.com](https://dash.deno.com)
3. Click "New Project"
4. Select your GitHub repo
5. Set entrypoint to `main.ts`
6. Add environment variables:
   - `ANTHROPIC_API_KEY` = your Anthropic key
   - `GEMINI_API_KEY` = your Google Gemini key
7. Click Deploy

### Option 2: Deploy via CLI

```bash
# Install Deno
# Windows: irm https://deno.land/install.ps1 | iex
# Mac/Linux: curl -fsSL https://deno.land/install.sh | sh

# Install deployctl
deno install -Arf jsr:@deno/deployctl

# Deploy
deployctl deploy --project=ai-api-proxy main.ts
```

Then add environment variables in the Deno Deploy dashboard.

## API Endpoints

### Anthropic Claude

```bash
POST /api/anthropic/messages

# Request body (same as Anthropic API):
{
  "model": "claude-3-5-haiku-20241022",
  "max_tokens": 1024,
  "messages": [{"role": "user", "content": "Hello"}]
}
```

### Google Gemini

```bash
POST /api/gemini/generate

# Request body:
{
  "model": "gemini-1.5-flash",
  "contents": [{"parts": [{"text": "Hello"}]}]
}
```

### Health Check

```bash
GET /health
```

## Updating Your Apps

### Mobile Apps (Expo/React Native)

Update your `.env` file:

```bash
# Remove old key:
# EXPO_PUBLIC_ANTHROPIC_API_KEY=sk-ant-xxx

# Add proxy URL:
EXPO_PUBLIC_AI_PROXY_URL=https://your-project.deno.dev
```

### Web Apps

```javascript
// OLD (insecure):
const response = await fetch('https://api.anthropic.com/v1/messages', {
  headers: { 'x-api-key': 'sk-ant-xxx' },
  body: JSON.stringify(payload)
});

// NEW (secure):
const response = await fetch('https://your-project.deno.dev/api/anthropic/messages', {
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload)
});
```

## Local Development

```bash
# Set environment variables
export ANTHROPIC_API_KEY=sk-ant-xxx
export GEMINI_API_KEY=xxx

# Run locally
deno task dev
```

## Rate Limiting

Built-in rate limiting: 60 requests per minute per IP.

## Cost

| Monthly Requests | Cost |
|-----------------|------|
| < 3,000,000     | $0 (free tier) |
| Unlimited       | $10/month (Pro) |

Deno Deploy free tier: 100,000 requests/day

## Project Structure

```
api-proxy/
├── main.ts       # Main server code
├── deno.json     # Deno configuration
└── README.md
```
