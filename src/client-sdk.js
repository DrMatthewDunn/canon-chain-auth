// client-sdk.js

let currentToken = null;

/**
 * 1. INITIALIZE (Call on page load)
 * Assumes you have the Cloudflare Turnstile widget rendered on the page
 */
async function initSession(turnstileResponse) {
  try {
    const res = await fetch('https://maker.yoursite.com/api/init-session', {
      method: 'POST',
      body: JSON.stringify({ cfTurnstileResponse: turnstileResponse })
    });
    
    if (!res.ok) throw new Error('Bot check failed');
    
    const data = await res.json();
    currentToken = data.token;
    console.log("Session started!");
    
  } catch (e) {
    console.error("Could not init session", e);
  }
}

/**
 * 2. THE FETCH WRAPPER (Self-Healing)
 * Use this function instead of standard fetch() for beacon calls
 */
async function callBeacon(url, options = {}) {
  // A. Prepare Headers
  const headers = { ...options.headers, 'X-Custom-Auth': currentToken };
  
  // B. First Attempt
  let response = await fetch(url, { ...options, headers });

  // C. Handle "Token Expired" (419)
  if (response.status === 419) {
    console.warn("Token expired. Attempting refresh...");

    // D. Ask Key Maker for new token using old one
    const refreshRes = await fetch('https://maker.yoursite.com/api/refresh-token', {
      method: 'POST',
      headers: { 'X-Old-Token': currentToken }
    });

    if (refreshRes.ok) {
      const data = await refreshRes.json();
      currentToken = data.token; // Update global token

      // E. Retry Original Request with new token
      headers['X-Custom-Auth'] = currentToken;
      response = await fetch(url, { ...options, headers });
    } else {
      console.error("Session dead. User must reload/solve CAPTCHA.");
      // Optional: window.location.reload();
    }
  }

  return response;
}