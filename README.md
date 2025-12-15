# canon-chain-auth

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
/*
 * Canon Chain Protocol - crypto-utils.js
 * Copyright (c) 2025 [Matthew Dunn]
 * Licensed under MIT (https://opensource.org/licenses/MIT)
 */

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
