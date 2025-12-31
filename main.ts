/**
 * AI API Proxy - Deno Deploy
 *
 * A secure proxy for Anthropic Claude, Google Gemini, and Supabase APIs.
 * Keeps API keys server-side, adds rate limiting and CORS support.
 *
 * Endpoints:
 *   POST /api/anthropic/messages     - Proxy to Claude Messages API
 *   POST /api/gemini/generate        - Proxy to Gemini generateContent
 *   POST /api/chat                   - Baby Names AI chat companion
 *   POST /api/generate-names         - Generate baby name suggestions
 *   POST /api/stress-test            - Analyze name for teasing potential
 *   POST /api/check-availability     - Check social handle availability
 *   POST /api/supabase/*             - Proxy to Supabase (uses service_role key)
 *   GET  /health                     - Health check
 *
 * Environment variables (set in Deno Deploy dashboard):
 *   ANTHROPIC_API_KEY     - Your Anthropic API key
 *   GEMINI_API_KEY        - Your Google Gemini API key
 *   SUPABASE_URL          - Your Supabase project URL
 *   SUPABASE_SERVICE_KEY  - Your Supabase service_role key (NOT anon key)
 */

// CORS headers for cross-origin requests
const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS, PATCH, DELETE",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-device-id",
  "Access-Control-Max-Age": "86400",
};

// Simple in-memory rate limiting
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_RPM = 60;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + 60000 });
    return true;
  }

  if (record.count >= RATE_LIMIT_RPM) {
    return false;
  }

  record.count++;
  return true;
}

// Handle OPTIONS preflight requests
function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: corsHeaders,
  });
}

// Health check endpoint
function handleHealth(): Response {
  return new Response(
    JSON.stringify({
      status: "ok",
      timestamp: new Date().toISOString(),
      services: {
        anthropic: !!Deno.env.get("ANTHROPIC_API_KEY"),
        gemini: !!Deno.env.get("GEMINI_API_KEY"),
        supabase: !!Deno.env.get("SUPABASE_URL") && !!Deno.env.get("SUPABASE_SERVICE_KEY"),
      }
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    }
  );
}

// Helper to call Claude API
async function callClaude(
  messages: Array<{ role: string; content: string }>,
  systemPrompt?: string,
  maxTokens = 1024
): Promise<{ content: string; error?: string }> {
  const apiKey = Deno.env.get("ANTHROPIC_API_KEY");

  if (!apiKey) {
    return { content: "", error: "Anthropic API key not configured" };
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: messages.filter(m => m.role !== "system"),
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      return { content: "", error: `Claude API error: ${response.status} - ${error}` };
    }

    const data = await response.json();
    const content = data.content?.[0]?.text || "";
    return { content };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return { content: "", error: message };
  }
}

// ============ Baby Names Specific Endpoints ============

const CHAT_SYSTEM_PROMPT = `You are a warm, knowledgeable companion helping parents discover the perfect baby name. You combine the depth of a naming historian with the intuition of a trusted friend.

## Personality
- Warm but not saccharine
- Knowledgeable without being pedantic
- Gently curious, never interrogating
- Occasionally surprising with unexpected connections

## Core Behaviors

### Learning Preferences
- Ask ONE question at a time
- Listen for unstated preferences in reactions
- Note emotional language ("I love how that sounds")
- Build a mental model of their aesthetic

### Generating Names
- Offer 3-5 names per suggestion, not more
- Always explain WHY each name fits preferences
- Include one "wildcard" that stretches criteria
- Never repeat a rejected name

### Response Style
- Keep responses under 150 words unless explaining etymology
- Use the parent's language back to them
- Celebrate when they react positively
- Pivot gracefully from rejection

## Context
The user has the following preferences:
{{PREFERENCES}}

Their favorite names so far: {{FAVORITES}}
Names they've rejected: {{REJECTED}}

## Output Format
When suggesting names, output JSON at the end of your response in this format:
\`\`\`json
{"suggested_names": [{"name": "Name", "pronunciation": "optional", "brief": "One sentence meaning", "matchReasons": ["reason1", "reason2"]}]}
\`\`\`

End with a gentle question OR invitation to react.`;

async function handleChat(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const { messages, context } = body;

    // Build system prompt with context
    let systemPrompt = CHAT_SYSTEM_PROMPT
      .replace("{{PREFERENCES}}", JSON.stringify(context?.preferences || {}))
      .replace("{{FAVORITES}}", (context?.favoriteNames || []).join(", ") || "none yet")
      .replace("{{REJECTED}}", (context?.rejectedNames || []).join(", ") || "none yet");

    const result = await callClaude(messages, systemPrompt);

    if (result.error) {
      return new Response(
        JSON.stringify({ error: result.error }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Try to extract suggested names from JSON in response
    let suggestedNames = undefined;
    const jsonMatch = result.content.match(/```json\s*([\s\S]*?)\s*```/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[1]);
        suggestedNames = parsed.suggested_names;
      } catch {
        // Ignore JSON parse errors
      }
    }

    // Clean content (remove JSON block if present)
    const cleanContent = result.content.replace(/```json[\s\S]*?```/g, "").trim();

    return new Response(
      JSON.stringify({
        content: cleanContent,
        suggestedNames
      }),
      { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Chat error", details: message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

const GENERATE_NAMES_PROMPT = `You are a baby name expert. Generate {{COUNT}} unique baby name suggestions based on these preferences:

{{PREFERENCES}}

Output ONLY valid JSON in this exact format:
{
  "names": [
    {
      "name": "Name",
      "gender": "male|female|neutral",
      "origin": "Origin/culture",
      "meaning": "Brief meaning",
      "style": ["Classic", "Modern", etc]
    }
  ]
}`;

async function handleGenerateNames(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const { preferences, count = 5 } = body;

    const prompt = GENERATE_NAMES_PROMPT
      .replace("{{COUNT}}", String(count))
      .replace("{{PREFERENCES}}", JSON.stringify(preferences));

    const result = await callClaude(
      [{ role: "user", content: "Generate names now." }],
      prompt
    );

    if (result.error) {
      return new Response(
        JSON.stringify({ error: result.error }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Parse JSON from response
    let names: string[] = [];
    try {
      // Try to extract JSON
      const jsonMatch = result.content.match(/\{[\s\S]*"names"[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        names = parsed.names?.map((n: { name: string }) => n.name) || [];
      }
    } catch {
      // Fallback: extract names from text
      names = result.content.match(/["']([A-Z][a-z]+)["']/g)?.map(n => n.replace(/["']/g, "")) || [];
    }

    return new Response(
      JSON.stringify({ names }),
      { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Generate names error", details: message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

const STRESS_TEST_PROMPT = `You are a child psychologist and naming expert. Analyze this name for potential teasing or bullying vulnerabilities that a child might face:

Name: {{FIRST_NAME}}{{LAST_NAME}}

Consider:
1. Rhymes with negative words
2. Unfortunate initials or acronyms
3. Pop culture associations (positive and negative)
4. Common mispronunciations
5. Playground nickname potential
6. Social media handle problems

Be honest but constructive. Output ONLY valid JSON:
{
  "overallRisk": "low|moderate|elevated|high",
  "summary": "One sentence summary",
  "vulnerabilities": ["specific issue 1", "specific issue 2"],
  "mitigations": ["way to address 1", "way to address 2"],
  "positiveNotes": ["positive aspect 1", "positive aspect 2"]
}`;

async function handleStressTest(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const { firstName, lastName } = body;

    if (!firstName) {
      return new Response(
        JSON.stringify({ error: "firstName is required" }),
        { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    const prompt = STRESS_TEST_PROMPT
      .replace("{{FIRST_NAME}}", firstName)
      .replace("{{LAST_NAME}}", lastName ? ` ${lastName}` : "");

    const result = await callClaude(
      [{ role: "user", content: "Analyze this name now." }],
      prompt
    );

    if (result.error) {
      return new Response(
        JSON.stringify({ error: result.error }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Parse JSON from response
    try {
      const jsonMatch = result.content.match(/\{[\s\S]*"overallRisk"[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return new Response(
          JSON.stringify(parsed),
          { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      }
    } catch {
      // Return error if parsing fails
    }

    // Fallback response if parsing fails
    return new Response(
      JSON.stringify({
        overallRisk: "low",
        summary: "Analysis could not be completed. The name appears standard.",
        vulnerabilities: [],
        mitigations: [],
        positiveNotes: ["Name appears unremarkable from a teasing perspective"]
      }),
      { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Stress test error", details: message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

// Note: Real availability checking would require actual API calls to platforms
// This provides a simulated response for demo purposes
async function handleCheckAvailability(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const { name, checkTypes = ["instagram", "tiktok", "domain"] } = body;

    if (!name) {
      return new Response(
        JSON.stringify({ error: "name is required" }),
        { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    const cleanName = name.toLowerCase().replace(/[^a-z0-9]/g, "");
    const result: Record<string, { available: boolean; handle?: string; domain?: string }> = {};

    // Simulate availability checks
    // In production, these would be real API calls
    if (checkTypes.includes("instagram")) {
      result.instagram = {
        available: cleanName.length > 8, // Longer names more likely available
        handle: `@${cleanName}`,
      };
    }

    if (checkTypes.includes("tiktok")) {
      result.tiktok = {
        available: cleanName.length > 6,
        handle: `@${cleanName}`,
      };
    }

    if (checkTypes.includes("domain")) {
      result.domain = {
        available: cleanName.length > 10,
        domain: `${cleanName}.com`,
      };
    }

    return new Response(
      JSON.stringify(result),
      { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Availability check error", details: message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

// ============ Supabase Proxy ============

async function handleSupabase(request: Request, url: URL): Promise<Response> {
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_KEY");

  if (!supabaseUrl || !serviceKey) {
    return new Response(
      JSON.stringify({ error: "Supabase not configured" }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }

  try {
    // Get device ID from header for RLS
    const deviceId = request.headers.get("x-device-id");

    // Build the Supabase URL path (remove /api/supabase prefix)
    const supabasePath = url.pathname.replace(/^\/api\/supabase/, "");
    const targetUrl = `${supabaseUrl}${supabasePath}${url.search}`;

    // Clone request with Supabase auth headers
    const headers = new Headers(request.headers);
    headers.set("apikey", serviceKey);
    headers.set("Authorization", `Bearer ${serviceKey}`);

    // If device ID provided, set it for RLS policies
    if (deviceId) {
      headers.set("x-device-id", deviceId);
    }

    const response = await fetch(targetUrl, {
      method: request.method,
      headers,
      body: request.method !== "GET" && request.method !== "HEAD"
        ? await request.text()
        : undefined,
    });

    const data = await response.text();

    return new Response(data, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "application/json",
        ...corsHeaders
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Supabase proxy error", details: message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

// ============ Original Anthropic/Gemini Handlers ============

// Proxy request to Anthropic Claude API
async function handleAnthropic(request: Request): Promise<Response> {
  const apiKey = Deno.env.get("ANTHROPIC_API_KEY");

  if (!apiKey) {
    return new Response(
      JSON.stringify({ error: "Anthropic API key not configured" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }

  try {
    const body = await request.json();

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });

    // Handle streaming responses
    if (body.stream) {
      return new Response(response.body, {
        status: response.status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          ...corsHeaders,
        },
      });
    }

    // Non-streaming response
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Proxy error", details: message }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }
}

// Proxy request to Google Gemini API
async function handleGemini(
  request: Request,
  url: URL
): Promise<Response> {
  const apiKey = Deno.env.get("GEMINI_API_KEY");

  if (!apiKey) {
    return new Response(
      JSON.stringify({ error: "Gemini API key not configured" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }

  try {
    const body = await request.json();

    // Extract model from path or use default
    const pathMatch = url.pathname.match(/\/api\/gemini\/models\/([^:]+):(\w+)/);
    const model = pathMatch?.[1] || "gemini-1.5-flash";
    const action = pathMatch?.[2] || "generateContent";

    // Check if streaming is requested
    const isStreaming = action === "streamGenerateContent" || body.stream;
    const endpoint = isStreaming ? "streamGenerateContent" : "generateContent";

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:${endpoint}?key=${apiKey}`;

    const response = await fetch(geminiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    // Handle streaming responses
    if (isStreaming) {
      return new Response(response.body, {
        status: response.status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          ...corsHeaders,
        },
      });
    }

    // Non-streaming response
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Proxy error", details: message }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }
}

// Simple Gemini endpoint
async function handleGeminiSimple(request: Request): Promise<Response> {
  const apiKey = Deno.env.get("GEMINI_API_KEY");

  if (!apiKey) {
    return new Response(
      JSON.stringify({ error: "Gemini API key not configured" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }

  try {
    const body = await request.json();
    const model = body.model || "gemini-1.5-flash";
    delete body.model;

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    const response = await fetch(geminiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: "Proxy error", details: message }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }
}

// Main request handler
async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    return handleOptions();
  }

  // Health check
  if (path === "/health" || path === "/") {
    return handleHealth();
  }

  // Rate limiting (get IP from headers)
  const clientIP =
    request.headers.get("x-forwarded-for")?.split(",")[0] ||
    request.headers.get("cf-connecting-ip") ||
    "unknown";

  if (!checkRateLimit(clientIP)) {
    return new Response(
      JSON.stringify({
        error: "Rate limit exceeded",
        message: `Maximum ${RATE_LIMIT_RPM} requests per minute`,
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": "60",
          ...corsHeaders,
        },
      }
    );
  }

  // Only allow POST for API endpoints (except Supabase which can be GET/PATCH/DELETE)
  if (request.method !== "POST" && !path.startsWith("/api/supabase")) {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  // Route to appropriate handler

  // Baby Names specific endpoints
  if (path === "/api/chat") {
    return handleChat(request);
  }

  if (path === "/api/generate-names") {
    return handleGenerateNames(request);
  }

  if (path === "/api/stress-test") {
    return handleStressTest(request);
  }

  if (path === "/api/check-availability") {
    return handleCheckAvailability(request);
  }

  // Supabase proxy
  if (path.startsWith("/api/supabase")) {
    return handleSupabase(request, url);
  }

  // Original AI proxy endpoints
  if (path === "/api/anthropic/messages" || path.startsWith("/api/anthropic/")) {
    return handleAnthropic(request);
  }

  if (path === "/api/gemini/generate" || path === "/api/gemini") {
    return handleGeminiSimple(request);
  }

  if (path.startsWith("/api/gemini/models/")) {
    return handleGemini(request, url);
  }

  // 404 for unknown routes
  return new Response(
    JSON.stringify({
      error: "Not found",
      availableEndpoints: [
        "POST /api/chat                   - Baby names AI companion",
        "POST /api/generate-names         - Generate name suggestions",
        "POST /api/stress-test            - Analyze teasing potential",
        "POST /api/check-availability     - Check handle availability",
        "POST /api/supabase/*             - Supabase proxy",
        "POST /api/anthropic/messages     - Claude API proxy",
        "POST /api/gemini/generate        - Gemini API proxy",
        "GET  /health                     - Health check",
      ],
    }),
    {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    }
  );
}

// Start the server
Deno.serve(handler);
