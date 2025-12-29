/**
 * AI API Proxy - Deno Deploy
 *
 * A secure proxy for Anthropic Claude and Google Gemini APIs.
 * Keeps API keys server-side, adds rate limiting and CORS support.
 *
 * Endpoints:
 *   POST /api/anthropic/messages     - Proxy to Claude Messages API
 *   POST /api/gemini/generate        - Proxy to Gemini generateContent
 *   GET  /health                     - Health check
 *
 * Environment variables (set in Deno Deploy dashboard):
 *   ANTHROPIC_API_KEY - Your Anthropic API key
 *   GEMINI_API_KEY    - Your Google Gemini API key
 */

// CORS headers for cross-origin requests
const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
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
    JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }),
    {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    }
  );
}

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

  // Only allow POST for API endpoints
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  // Route to appropriate handler
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
        "POST /api/anthropic/messages",
        "POST /api/gemini/generate",
        "POST /api/gemini/models/{model}:generateContent",
        "GET /health",
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
