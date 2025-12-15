// worker-guard.js
import { inspectToken } from './crypto-utils.js';

export default {
  async fetch(request, env) {
    // 1. Extract Token
    const token = request.headers.get("X-Custom-Auth");

    // 2. Validate
    const result = await inspectToken(token, env.TICKET_SECRET);

    // 3. Handle Statuses
    if (result.status === 'VALID') {
      // --- SUCCESS: DO THE ACTUAL WORK HERE ---
      return new Response("Welcome, legit user.", { status: 200 });
    }

    if (result.status === 'EXPIRED_FRESH') {
      // 419: Tell client "You are legit, but need a new ticket"
      return new Response("Token Expired", { status: 419 }); 
    }

    // INVALID or DEAD
    return new Response("Forbidden", { status: 403 });
  }
};