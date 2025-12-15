// canon-utils.js

/**
 * Converts ArrayBuffer to Hex String
 */
export function arrayBufferToHex(buffer) {
    return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
  }
  
  /**
   * Converts Hex String to ArrayBuffer
   */
  export function hexToArrayBuffer(hex) {
    const match = hex.match(/.{1,2}/g);
    if (!match) return new Uint8Array();
    return new Uint8Array(match.map(byte => parseInt(byte, 16)));
  }
  
  /**
   * Encrypts a payload into a token string "IV:CIPHER"
   */
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
  
  /**
   * Decrypts a token string and checks expiry
   * Returns: { status: 'VALID' | 'EXPIRED_FRESH' | 'DEAD' | 'INVALID', payload: string }
   */
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
        { name: "AES-GCM", iv: hexToArrayBuffer(ivHex) },
        key,
        hexToArrayBuffer(cipherHex)
      );
  
      const expiryTimestamp = parseInt(dec.decode(decryptedBuffer));
      const now = Date.now();
  
      // 1. Perfectly Valid
      if (now < expiryTimestamp) {
        return { status: 'VALID', payload: expiryTimestamp };
      }
  
      // 2. Expired, but within 60 min grace period (Allow Refresh)
      const gracePeriod = 60 * 60 * 1000; 
      if (now < expiryTimestamp + gracePeriod) {
        return { status: 'EXPIRED_FRESH', payload: expiryTimestamp };
      }
  
      // 3. Too old
      return { status: 'DEAD' };
  
    } catch (e) {
      return { status: 'INVALID' }; // Crypto failed (bad key/tampering)
    }
  }