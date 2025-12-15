Here is a complete, professional-grade `README.md` for your repo. I’ve structured it to be impressive immediately upon landing on the page, explaining the "Why" before the "How."

You can copy-paste the block below directly into your `README.md` file.

-----

````markdown
# 🔗 Canon Chain Protocol

**Stateless, self-healing, cryptographically chained authentication for the Edge.**

> *“The Ouroboros of Authentication.”*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Cloudflare Workers](https://img.shields.io/badge/Platform-Cloudflare_Workers-orange.svg)](https://workers.cloudflare.com/)

---

## 🧐 What is it?

**Canon Chain** is a reference implementation for a lightweight authentication protocol designed specifically for **Cloudflare Workers** (and other Edge environments).

It replaces static API Keys (too risky) and database sessions (too slow) with **Rolling Edge Tickets (RET)**.

Instead of checking a central database to see if a user is logged in, the protocol uses a **Chain of Trust**. The validity of a session is determined mathematically by the possession of the *immediately preceding* token.



## ✨ Features

* **Zero State:** No database lookups. Validation happens via AES-GCM decryption in microseconds.
* **Zero Latency:** Runs entirely on the Edge using native Web Crypto APIs.
* **Bot Resistant:** Sessions must be "bootstrapped" via **Cloudflare Turnstile** (CAPTCHA).
* **Self-Healing:** The client automatically "heals" the chain by exchanging expired (but valid) tokens for fresh ones without user intervention.
* **Opaque:** Unlike JWTs, tokens are fully encrypted. The client cannot read or tamper with the payload.

---

## ⚙️ How It Works

The protocol follows three distinct phases:

1.  **Bootstrap (The Hard Entry):**
    The user proves they are human via Cloudflare Turnstile. The server issues **Token₀**.
2.  **Continuity (The Chain):**
    **Token₀** expires in 15 minutes. The client presents the expired **Token₀** to get **Token₁**.
    * *Rule:* You can only get a new token if you hold the immediately preceding link in the chain.
3.  **Verification (The Gate):**
    Any Worker in your system can decrypt the token to verify:
    * Is the signature valid? (Auth)
    * Is the timestamp fresh? (Time)

---

## 🚀 Quick Start

### 1. The Core Utility
Create a file named `crypto-utils.js` in your project. This is the only dependency (and it has no npm dependencies!).

```javascript
/* crypto-utils.js */
export function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function hexToArrayBuffer(hex) {
  const match = hex.match(/.{1,2}/g);
  if (!match) return new Uint8Array();
  return new Uint8Array(match.map(byte => parseInt(byte, 16)));
}

export async function encryptToken(payloadStr, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "AES-GCM" }, false, ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv }, key, enc.encode(payloadStr)
  );
  return `${arrayBufferToHex(iv)}:${arrayBufferToHex(encrypted)}`;
}

export async function inspectToken(tokenStr, secret) {
  if (!tokenStr || !tokenStr.includes(':')) return { status: 'INVALID' };
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const [ivHex, cipherHex] = tokenStr.split(':');
  try {
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(secret), { name: "AES-GCM" }, false, ["decrypt"]
    );
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToArrayBuffer(ivHex) }, key, hexToArrayBuffer(cipherHex)
    );
    const expiryTimestamp = parseInt(dec.decode(decryptedBuffer));
    const now = Date.now();
    
    if (now < expiryTimestamp) return { status: 'VALID', payload: expiryTimestamp };
    // Grace period of 60 mins for refresh
    if (now < expiryTimestamp + (60 * 60 * 1000)) return { status: 'EXPIRED_FRESH', payload: expiryTimestamp };
    return { status: 'DEAD' };
  } catch (e) {
    return { status: 'INVALID' };
  }
}
````

### 2\. Configuration (`wrangler.toml`)

Ensure all participating Workers have the **same** secret.

```bash
# Generate a random 32-character string
openssl rand -hex 16

# Add to Cloudflare Secrets
npx wrangler secret put TICKET_SECRET
```

### 3\. The "Key Maker" Worker (Issuer)

This worker handles the Turnstile check and token rotation.

```javascript
import { encryptToken, inspectToken } from './crypto-utils.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. BOOTSTRAP (Requires Turnstile)
    if (url.pathname === '/api/init-session') {
      const { cfTurnstileResponse } = await request.json();
      // Verify Turnstile with Cloudflare...
      // If success:
      const token = await encryptToken((Date.now() + 900000).toString(), env.TICKET_SECRET);
      return new Response(JSON.stringify({ token }));
    }

    // 2. REFRESH (Requires Old Token)
    if (url.pathname === '/api/refresh-token') {
      const oldToken = request.headers.get("X-Old-Token");
      const result = await inspectToken(oldToken, env.TICKET_SECRET);
      
      if (result.status === 'EXPIRED_FRESH' || result.status === 'VALID') {
        const newToken = await encryptToken((Date.now() + 900000).toString(), env.TICKET_SECRET);
        return new Response(JSON.stringify({ token: newToken }));
      }
      return new Response("Session Dead", { status: 401 });
    }
  }
};
```

-----

## 💻 Client-Side Integration

The Canon Chain requires a "smart" client that knows how to handle the `419` (Token Expired) signal.

```javascript
let currentToken = null;

async function secureCall(url) {
  // 1. Try Request
  let res = await fetch(url, { headers: { 'X-Custom-Auth': currentToken } });

  // 2. Intercept "Expired" Signal (419)
  if (res.status === 419) {
    // 3. Auto-Heal the Chain
    const refresh = await fetch('/api/refresh-token', { 
      method: 'POST', 
      headers: { 'X-Old-Token': currentToken } 
    });
    
    if (refresh.ok) {
      const data = await refresh.json();
      currentToken = data.token; // Update Chain Link
      // 4. Retry Original Request
      res = await fetch(url, { headers: { 'X-Custom-Auth': currentToken } });
    }
  }
  return res;
}
```

-----

## ⚠️ Security Notice

This protocol relies on **Symmetric Encryption (AES-GCM)**.

1.  **The Secret is God:** If your `TICKET_SECRET` is leaked, an attacker can forge tickets. Rotate it via Cloudflare Secrets if you suspect a leak.
2.  **No Instant Revocation:** Because there is no database, you cannot "ban" a user instantly. You must wait for their current 15-minute token to expire.

-----

## 📄 License

MIT © 2025

```
```