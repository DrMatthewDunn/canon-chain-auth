// worker-maker.js
import { encryptToken, inspectToken } from './crypto-utils.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- ENDPOINT 1: INIT SESSION (Requires Turnstile) ---
    if (url.pathname === '/api/init-session' && request.method === 'POST') {
      const body = await request.json();

      // A. Verify Turnstile
      const tsResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY, // From Cloudflare Dashboard
          response: body.cfTurnstileResponse
        })
      });
      const outcome = await tsResult.json();
      if (!outcome.success) return new Response("Bot detected", { status: 403 });

      // B. Generate First Token (15 mins)
      const expiry = Date.now() + (15 * 60 * 1000); 
      const token = await encryptToken(expiry.toString(), env.TICKET_SECRET);

      return new Response(JSON.stringify({ token }));
    }

    // --- ENDPOINT 2: REFRESH TOKEN (Requires Old Valid Token) ---
    if (url.pathname === '/api/refresh-token' && request.method === 'POST') {
      const oldToken = request.headers.get("X-Old-Token");
      
      // A. Inspect the Old Token
      const result = await inspectToken(oldToken, env.TICKET_SECRET);

      // B. Only allow if it was valid recently ('EXPIRED_FRESH')
      if (result.status === 'EXPIRED_FRESH' || result.status === 'VALID') {
        const newExpiry = Date.now() + (15 * 60 * 1000);
        const newToken = await encryptToken(newExpiry.toString(), env.TICKET_SECRET);
        return new Response(JSON.stringify({ token: newToken }));
      }

      // C. Chain Broken
      return new Response("Session Dead", { status: 401 });
    }

    return new Response("Not Found", { status: 404 });
  }
};