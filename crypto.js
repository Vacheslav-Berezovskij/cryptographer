/**
 * crypto.js (ES module)
 *
 * Browser-side cryptographic helpers for ephemeral ECDH/X25519 sessions.
 *
 * SECURITY NOTES:
 * - Keys generated here are intended to be ephemeral (single-message/session).
 * - Never persist private keys, shared secrets, or derived AEAD keys to storage/logs.
 * - Always authenticate ciphertext (e.g., AES-GCM tag verification) before use.
 * - Prefer X25519 when available; fallback to P-256 only for compatibility.
 */

const subtle = globalThis?.crypto?.subtle;

if (!subtle) {
  throw new Error('WebCrypto subtle API is not available in this environment.');
}

/**
 * Generate cryptographically secure random bytes.
 * @param {number} n
 * @returns {Promise<Uint8Array>}
 */
export async function randomBytes(n) {
  if (!Number.isInteger(n) || n <= 0) {
    throw new TypeError('randomBytes(n): n must be a positive integer.');
  }
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Encode bytes to base64 (standard base64 with padding).
 * @param {ArrayBuffer|Uint8Array} input
 * @returns {Promise<string>}
 */
export async function base64Encode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/**
 * Decode base64 string to bytes.
 * @param {string} b64
 * @returns {Promise<Uint8Array>}
 */
export async function base64Decode(b64) {
  if (typeof b64 !== 'string' || b64.length === 0) {
    throw new TypeError('base64Decode(b64): b64 must be a non-empty string.');
  }
  let binary;
  try {
    binary = atob(b64);
  } catch {
    throw new Error('Invalid base64 input.');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Returns true if X25519 appears supported by WebCrypto.
 * @returns {Promise<boolean>}
 */
async function isX25519Supported() {
  try {
    const pair = await subtle.generateKey(
      { name: 'X25519' },
      false,
      ['deriveBits']
    );
    return !!pair?.privateKey && !!pair?.publicKey;
  } catch {
    return false;
  }
}

/**
 * Generate ephemeral key pair, preferring X25519 and falling back to ECDH P-256.
 *
 * @returns {Promise<{algorithm: 'X25519' | 'P-256', privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function generateEphemeralKeyPair() {
  try {
    if (await isX25519Supported()) {
      const pair = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      return {
        algorithm: 'X25519',
        privateKey: pair.privateKey,
        publicKey: pair.publicKey
      };
    }

    const pair = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits']
    );

    return {
      algorithm: 'P-256',
      privateKey: pair.privateKey,
      publicKey: pair.publicKey
    };
  } catch (err) {
    throw new Error(`Failed to generate ephemeral key pair: ${err?.message || String(err)}`);
  }
}

/**
 * Export public key to base64.
 * - X25519 => raw
 * - P-256 => spki
 *
 * @param {CryptoKey} publicKey
 * @param {'X25519'|'P-256'} algorithm
 * @returns {Promise<string>}
 */
export async function exportPublicKeyBase64(publicKey, algorithm) {
  try {
    const format = algorithm === 'X25519' ? 'raw' : 'spki';
    const raw = await subtle.exportKey(format, publicKey);
    return base64Encode(raw);
  } catch (err) {
    throw new Error(`Failed to export public key (${algorithm}): ${err?.message || String(err)}`);
  }
}

/**
 * Import remote public key from base64.
 * - X25519 => raw
 * - P-256 => spki
 *
 * @param {string} b64
 * @param {'X25519'|'P-256'} algorithm
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKeyBase64(b64, algorithm) {
  try {
    const bytes = await base64Decode(b64);

    if (algorithm === 'X25519') {
      return await subtle.importKey(
        'raw',
        bytes,
        { name: 'X25519' },
        false,
        []
      );
    }

    if (algorithm === 'P-256') {
      return await subtle.importKey(
        'spki',
        bytes,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );
    }

    throw new Error(`Unsupported algorithm for import: ${algorithm}`);
  } catch (err) {
    throw new Error(`Failed to import public key (${algorithm}): ${err?.message || String(err)}`);
  }
}

/**
 * Derive raw shared secret bytes using local private key + remote public key.
 *
 * @param {CryptoKey} localPrivateKey
 * @param {CryptoKey} remotePublicKey
 * @param {'X25519'|'P-256'} algorithm
 * @returns {Promise<Uint8Array>}
 */
export async function deriveSharedSecret(localPrivateKey, remotePublicKey, algorithm) {
  try {
    const deriveParams =
      algorithm === 'X25519'
        ? { name: 'X25519', public: remotePublicKey }
        : { name: 'ECDH', public: remotePublicKey };

    const bits = await subtle.deriveBits(deriveParams, localPrivateKey, 256);
    return new Uint8Array(bits);
  } catch (err) {
    throw new Error(`Failed to derive shared secret (${algorithm}): ${err?.message || String(err)}`);
  }
}

/**
 * HKDF-SHA-256 over raw shared secret => 256-bit AEAD key bytes.
 *
 * SECURITY NOTE:
 * - Use per-session salt (random 16/32 bytes).
 * - Use context-bound info (protocol/version/session IDs/roles).
 *
 * @param {ArrayBuffer|Uint8Array} rawSecret
 * @param {ArrayBuffer|Uint8Array} salt
 * @param {ArrayBuffer|Uint8Array} info
 * @returns {Promise<Uint8Array>} 32 bytes
 */
export async function deriveAeadKey(rawSecret, salt, info) {
  try {
    const ikm = rawSecret instanceof Uint8Array ? rawSecret : new Uint8Array(rawSecret);
    const saltBytes = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
    const infoBytes = info instanceof Uint8Array ? info : new Uint8Array(info);

    if (ikm.length === 0) throw new Error('rawSecret must not be empty.');
    if (saltBytes.length === 0) throw new Error('salt must not be empty.');

    const keyMaterial = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);

    const bits = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBytes,
        info: infoBytes
      },
      keyMaterial,
      256
    );

    return new Uint8Array(bits);
  } catch (err) {
    throw new Error(`Failed HKDF key derivation: ${err?.message || String(err)}`);
  }
}
