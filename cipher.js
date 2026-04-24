/**
 * cipher.js (ES module)
 *
 * AES-GCM helpers and final packet serialization for transport via MAX.
 *
 * SECURITY NOTES:
 * - AES-GCM requires unique IV per key. Always generate a fresh random 12-byte IV.
 * - HKDF salt should be random per message/session (recommended 16 or 32 bytes).
 * - AAD must be identical on encrypt/decrypt. Include stable fields (sender_id, version, ts).
 * - Do not log raw key bytes, plaintext, or decrypted content.
 */

import { randomBytes, base64Encode, base64Decode } from './crypto.js';

const subtle = globalThis?.crypto?.subtle;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const GCM_TAG_BYTES = 16;
const GCM_IV_BYTES = 12;
const HKDF_SALT_BYTES = 16;

if (!subtle) {
  throw new Error('WebCrypto subtle API is not available in this environment.');
}

/**
 * Canonical JSON stringify with sorted object keys.
 * Needed to keep AAD bytes stable across participants.
 * @param {unknown} value
 * @returns {string}
 */
function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((x) => stableStringify(x)).join(',')}]`;

  const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
    .join(',')}}`;
}

/**
 * Normalize AAD input into bytes.
 * @param {string|Uint8Array|ArrayBuffer|object|null|undefined} aad
 * @returns {Uint8Array}
 */
function normalizeAad(aad) {
  if (aad == null) return new Uint8Array(0);
  if (aad instanceof Uint8Array) return aad;
  if (aad instanceof ArrayBuffer) return new Uint8Array(aad);
  if (typeof aad === 'string') return textEncoder.encode(aad);
  if (typeof aad === 'object') return textEncoder.encode(stableStringify(aad));
  throw new TypeError('AAD must be string, bytes, object, or null/undefined.');
}

/**
 * Import 256-bit AES key from raw bytes.
 * @param {Uint8Array|ArrayBuffer} keyBytes
 * @returns {Promise<CryptoKey>}
 */
async function importAesKey(keyBytes) {
  const bytes = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);
  if (bytes.length !== 32) {
    throw new Error(`AES-256-GCM expects 32-byte key, got ${bytes.length}.`);
  }
  return subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Recommended helper: generate random HKDF salt (base64).
 * Use this salt as HKDF salt for deriving message AEAD key.
 * @returns {Promise<string>}
 */
export async function generateHkdfSaltBase64() {
  const salt = await randomBytes(HKDF_SALT_BYTES);
  return base64Encode(salt);
}

/**
 * Encrypt plaintext using AES-256-GCM.
 * @param {Uint8Array|ArrayBuffer} keyBytes 32-byte key
 * @param {string} plaintext UTF-8 text
 * @param {string|Uint8Array|ArrayBuffer|object|null|undefined} aad
 * @returns {Promise<{iv: string, ciphertext: string, tag: string}>}
 */
export async function encryptWithKey(keyBytes, plaintext, aad) {
  try {
    if (typeof plaintext !== 'string') {
      throw new TypeError('plaintext must be a string.');
    }

    const key = await importAesKey(keyBytes);
    const iv = await randomBytes(GCM_IV_BYTES);
    const aadBytes = normalizeAad(aad);
    const ptBytes = textEncoder.encode(plaintext);

    const encrypted = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aadBytes,
        tagLength: 128
      },
      key,
      ptBytes
    );

    const encBytes = new Uint8Array(encrypted);
    if (encBytes.length < GCM_TAG_BYTES) {
      throw new Error('Encrypted output too short to contain GCM tag.');
    }

    const ct = encBytes.slice(0, encBytes.length - GCM_TAG_BYTES);
    const tag = encBytes.slice(encBytes.length - GCM_TAG_BYTES);

    return {
      iv: await base64Encode(iv),
      ciphertext: await base64Encode(ct),
      tag: await base64Encode(tag)
    };
  } catch (err) {
    throw new Error(`AES-GCM encryption failed: ${err?.message || String(err)}`);
  }
}

/**
 * Decrypt AES-256-GCM payload.
 * @param {Uint8Array|ArrayBuffer} keyBytes 32-byte key
 * @param {{iv: string, ciphertext: string, tag: string}} payload base64 fields
 * @param {string|Uint8Array|ArrayBuffer|object|null|undefined} aad
 * @returns {Promise<string>} plaintext UTF-8
 */
export async function decryptWithKey(keyBytes, payload, aad) {
  try {
    if (!payload || typeof payload !== 'object') {
      throw new TypeError('payload must be an object with iv/ciphertext/tag.');
    }

    const { iv, ciphertext, tag } = payload;
    if (!iv || !ciphertext || !tag) {
      throw new Error('payload.iv, payload.ciphertext and payload.tag are required.');
    }

    const key = await importAesKey(keyBytes);
    const ivBytes = await base64Decode(iv);
    const ctBytes = await base64Decode(ciphertext);
    const tagBytes = await base64Decode(tag);

    if (ivBytes.length !== GCM_IV_BYTES) {
      throw new Error(`AES-GCM requires 12-byte IV, got ${ivBytes.length}.`);
    }
    if (tagBytes.length !== GCM_TAG_BYTES) {
      throw new Error(`AES-GCM requires 16-byte tag, got ${tagBytes.length}.`);
    }

    const aadBytes = normalizeAad(aad);
    const combined = new Uint8Array(ctBytes.length + tagBytes.length);
    combined.set(ctBytes, 0);
    combined.set(tagBytes, ctBytes.length);

    const plainBuf = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        additionalData: aadBytes,
        tagLength: 128
      },
      key,
      combined
    );

    return textDecoder.decode(plainBuf);
  } catch (err) {
    throw new Error(`AES-GCM decryption failed: ${err?.message || String(err)}`);
  }
}

/**
 * Build the final transport packet and serialize it as base64(JSON UTF-8).
 *
 * AAD guideline:
 * - Include sender_id (derived from senderPub), version, ts
 * - Use exactly this same aad object for encrypt/decrypt
 *
 * @param {string} senderPub base64 public key of sender
 * @param {string} iv base64 IV (12 bytes)
 * @param {string|{ciphertext: string, tag: string}} ciphertext base64 ciphertext or object with ciphertext+tag
 * @param {string} salt base64 HKDF salt (recommended random 16/32 bytes per message)
 * @param {number} version protocol version
 * @param {number} ts unix ms
 * @returns {Promise<string>} base64(JSON)
 */
export async function buildFinalPacket(senderPub, iv, ciphertext, salt, version, ts) {
  try {
    if (typeof senderPub !== 'string' || !senderPub) throw new Error('senderPub is required.');
    if (typeof iv !== 'string' || !iv) throw new Error('iv is required.');
    if (typeof salt !== 'string' || !salt) throw new Error('salt is required.');
    if (!Number.isInteger(version) || version <= 0) throw new Error('version must be positive integer.');
    if (!Number.isInteger(ts) || ts <= 0) throw new Error('ts must be unix time in ms.');

    let ct;
    let tag;
    if (typeof ciphertext === 'string') {
      ct = ciphertext;
      tag = null;
    } else if (ciphertext && typeof ciphertext === 'object') {
      ct = ciphertext.ciphertext;
      tag = ciphertext.tag ?? null;
    }

    if (!ct || typeof ct !== 'string') throw new Error('ciphertext is required.');

    const aad = {
      sender_id: senderPub,
      version,
      ts
    };

    const packet = {
      proto: 'max-e2e-dh',
      type: 'ciphertext',
      version,
      ts,
      sender_pub: senderPub,
      salt,
      iv,
      ciphertext: ct,
      ...(tag ? { tag } : {}),
      aad
    };

    const json = JSON.stringify(packet);
    return base64Encode(textEncoder.encode(json));
  } catch (err) {
    throw new Error(`Failed to build final packet: ${err?.message || String(err)}`);
  }
}

/**
 * Parse base64(JSON) packet from MAX transport.
 * @param {string} blob base64(JSON UTF-8)
 * @returns {Promise<{
 *   proto: string,
 *   type: string,
 *   version: number,
 *   ts: number,
 *   sender_pub: string,
 *   salt: string,
 *   iv: string,
 *   ciphertext: string,
 *   tag?: string,
 *   aad: { sender_id: string, version: number, ts: number }
 * }>}
 */
export async function parseFinalPacket(blob) {
  try {
    if (typeof blob !== 'string' || !blob) {
      throw new TypeError('blob must be a non-empty base64 string.');
    }

    const bytes = await base64Decode(blob);
    const json = textDecoder.decode(bytes);
    const obj = JSON.parse(json);

    const required = ['proto', 'type', 'version', 'ts', 'sender_pub', 'salt', 'iv', 'ciphertext', 'aad'];
    for (const k of required) {
      if (!(k in obj)) throw new Error(`Missing required field: ${k}`);
    }

    if (obj.proto !== 'max-e2e-dh') throw new Error('Unsupported proto.');
    if (obj.type !== 'ciphertext') throw new Error('Unsupported type.');
    if (!Number.isInteger(obj.version) || obj.version <= 0) throw new Error('Invalid version.');
    if (!Number.isInteger(obj.ts) || obj.ts <= 0) throw new Error('Invalid ts.');

    if (!obj.aad || typeof obj.aad !== 'object') throw new Error('Invalid aad.');
    if (obj.aad.sender_id !== obj.sender_pub) throw new Error('AAD sender_id mismatch.');
    if (obj.aad.version !== obj.version) throw new Error('AAD version mismatch.');
    if (obj.aad.ts !== obj.ts) throw new Error('AAD ts mismatch.');

    return obj;
  } catch (err) {
    throw new Error(`Failed to parse final packet: ${err?.message || String(err)}`);
  }
}
