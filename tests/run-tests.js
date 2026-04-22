import {
  generateEphemeralKeyPair,
  exportPublicKeyBase64,
  importPublicKeyBase64,
  deriveSharedSecret,
  deriveAeadKey,
  base64Encode,
  randomBytes
} from '../crypto.js';
import { encryptWithKey, decryptWithKey } from '../cipher.js';
import { PopupProtocolStateMachine, ROLES } from '../state-machine.js';

const encoder = new TextEncoder();

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assert failed');
}

function assertEq(a, b, msg) {
  if (a !== b) throw new Error(msg || `assertEq failed: ${a} !== ${b}`);
}

function assertBytesEq(a, b, msg) {
  assert(a.length === b.length, msg || `byte length mismatch: ${a.length} vs ${b.length}`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(msg || `byte mismatch at ${i}`);
    }
  }
}

const out = document.getElementById('out');
function log(line) {
  out.textContent += line + '\n';
}

async function test(name, fn) {
  try {
    await fn();
    log(`✅ ${name}`);
  } catch (e) {
    log(`❌ ${name}: ${e.message}`);
    throw e;
  }
}

async function supportsX25519() {
  try {
    await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    return true;
  } catch {
    return false;
  }
}

await test('Key generation returns X25519 or P-256', async () => {
  const kp = await generateEphemeralKeyPair();
  assert(['X25519', 'P-256'].includes(kp.algorithm), `unexpected algorithm: ${kp.algorithm}`);
});

await test('X25519 path works when available', async () => {
  const ok = await supportsX25519();
  if (!ok) {
    log('ℹ️ X25519 unavailable in this browser, test skipped.');
    return;
  }

  const a = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const b = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);

  const aPubRaw = await crypto.subtle.exportKey('raw', a.publicKey);
  const bPubRaw = await crypto.subtle.exportKey('raw', b.publicKey);

  const aPub = await importPublicKeyBase64(await base64Encode(aPubRaw), 'X25519');
  const bPub = await importPublicKeyBase64(await base64Encode(bPubRaw), 'X25519');

  const s1 = await deriveSharedSecret(a.privateKey, bPub, 'X25519');
  const s2 = await deriveSharedSecret(b.privateKey, aPub, 'X25519');
  assertBytesEq(s1, s2, 'X25519 secrets must match');
});

await test('ECDH P-256 fallback compatibility works', async () => {
  const a = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const b = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  const aPubSpki = await crypto.subtle.exportKey('spki', a.publicKey);
  const bPubSpki = await crypto.subtle.exportKey('spki', b.publicKey);

  const aPub = await importPublicKeyBase64(await base64Encode(aPubSpki), 'P-256');
  const bPub = await importPublicKeyBase64(await base64Encode(bPubSpki), 'P-256');

  const s1 = await deriveSharedSecret(a.privateKey, bPub, 'P-256');
  const s2 = await deriveSharedSecret(b.privateKey, aPub, 'P-256');
  assertBytesEq(s1, s2, 'P-256 secrets must match');
});

await test('deriveSharedSecret two sides produce equal raw secret', async () => {
  const a = await generateEphemeralKeyPair();
  const b = await generateEphemeralKeyPair();
  assertEq(a.algorithm, b.algorithm, 'for this test both sides should use same algorithm');

  const aPubB64 = await exportPublicKeyBase64(a.publicKey, a.algorithm);
  const bPubB64 = await exportPublicKeyBase64(b.publicKey, b.algorithm);

  const aPub = await importPublicKeyBase64(aPubB64, a.algorithm);
  const bPub = await importPublicKeyBase64(bPubB64, b.algorithm);

  const s1 = await deriveSharedSecret(a.privateKey, bPub, a.algorithm);
  const s2 = await deriveSharedSecret(b.privateKey, aPub, b.algorithm);

  assertBytesEq(s1, s2, 'shared secret mismatch');
});

await test('HKDF produces stable output for same input', async () => {
  const secret = encoder.encode('same secret');
  const salt = encoder.encode('same salt');
  const info = encoder.encode('same info');

  const k1 = await deriveAeadKey(secret, salt, info);
  const k2 = await deriveAeadKey(secret, salt, info);
  const k3 = await deriveAeadKey(secret, salt, encoder.encode('different info'));

  assertBytesEq(k1, k2, 'HKDF with same inputs must be stable');
  assert(hex(k1) !== hex(k3), 'HKDF with different info should differ');
});

await test('encrypt/decrypt works and detects tampering', async () => {
  const key = await randomBytes(32);
  const aad = { sender_id: 'A', version: 1, ts: Date.now() };
  const plaintext = 'hello secure world';

  const enc = await encryptWithKey(key, plaintext, aad);
  const dec = await decryptWithKey(key, enc, aad);
  assertEq(dec, plaintext, 'decrypted plaintext mismatch');

  // Tamper ciphertext byte
  const ct = atob(enc.ciphertext);
  const tampered = ct.slice(0, ct.length - 1) + String.fromCharCode(ct.charCodeAt(ct.length - 1) ^ 1);
  const tamperedPayload = {
    ...enc,
    ciphertext: btoa(tampered)
  };

  let failed = false;
  try {
    await decryptWithKey(key, tamperedPayload, aad);
  } catch {
    failed = true;
  }
  assert(failed, 'tampered payload must fail decryption');
});

await test('State machine performs full sender/receiver flow', async () => {
  const sender = new PopupProtocolStateMachine(ROLES.SENDER, { stepTimeoutMs: 30_000, sessionTtlMs: 120_000 });
  const receiver = new PopupProtocolStateMachine(ROLES.RECEIVER, { stepTimeoutMs: 30_000, sessionTtlMs: 120_000 });

  const s1 = await sender.startSender();
  assertEq(sender.state, 'waiting_for_ack', 'sender must wait for ack after params');

  const r1 = await receiver.receiveParams(s1.outgoing);
  assertEq(receiver.state, 'generated_priv', 'receiver must be in generated_priv after params+ack prep');

  const s2 = await sender.senderHandleAckAndBuildPub(r1.outgoing);
  assertEq(sender.state, 'waiting_for_pub', 'sender must wait for pub after sending pub');

  const r2 = await receiver.receiverHandlePubAndReply(s2.outgoing);
  assertEq(receiver.state, 'waiting_for_ciphertext', 'receiver must wait for ciphertext');

  const plaintext = 'state machine roundtrip ok';
  const s3 = await sender.senderHandlePubEncrypt(r2.outgoing, plaintext);
  assertEq(sender.state, 'encrypt_and_send', 'sender must end in encrypt_and_send');

  const r3 = await receiver.receiverDecryptFinalPacket(s3.outgoing);
  assertEq(receiver.state, 'decrypt', 'receiver must end in decrypt');
  assertEq(r3.extra.plaintext, plaintext, 'receiver plaintext mismatch');

  // one-time policy: key material should be wiped after completion
  assert(sender.ctx.aeadKeyBytes === null, 'sender key material must be wiped');
  assert(receiver.ctx.aeadKeyBytes === null, 'receiver key material must be wiped');
});

log('\nВсе тесты завершены.');
