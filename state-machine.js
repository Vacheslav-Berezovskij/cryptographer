/**
 * state-machine.js (ES module)
 *
 * Popup protocol state machine for MAX copy/paste flow.
 * Supports Sender and Receiver roles with strict step transitions,
 * per-step timeouts, user instructions, and error handling.
 */

import {
  base64Decode,
  generateEphemeralKeyPair,
  exportPublicKeyBase64,
  importPublicKeyBase64,
  deriveSharedSecret,
  deriveAeadKey
} from './crypto.js';

import {
  encryptWithKey,
  decryptWithKey,
  generateHkdfSaltBase64,
  buildFinalPacket,
  parseFinalPacket
} from './cipher.js';

const PROTO = 'max-e2e-dh';
const VERSION = 1;

const DEFAULTS = {
  stepTimeoutMs: 2 * 60 * 1000,
  sessionTtlMs: 5 * 60 * 1000
};

export const ROLES = Object.freeze({
  SENDER: 'sender',
  RECEIVER: 'receiver'
});

export const SENDER_STATES = Object.freeze([
  'idle',
  'sent_params',
  'waiting_for_ack',
  'generated_priv',
  'sent_pub',
  'waiting_for_pub',
  'computed_secret',
  'encrypt_and_send',
  'error',
  'expired'
]);

export const RECEIVER_STATES = Object.freeze([
  'idle',
  'received_params',
  'ack_params_sent',
  'generated_priv',
  'received_pub',
  'sent_pub',
  'computed_secret',
  'waiting_for_ciphertext',
  'decrypt',
  'error',
  'expired'
]);

function randomId() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function nowMs() {
  return Date.now();
}

function makeEnvelope({ type, sid, from, to, body }) {
  return {
    proto: PROTO,
    ver: VERSION,
    type,
    sid,
    msg_id: randomId(),
    ts: nowMs(),
    from,
    to,
    body
  };
}

function parseJsonSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

/**
 * Unified result returned by actions.
 * @typedef {{
 *   state: string,
 *   instruction: string,
 *   outgoing?: string,
 *   extra?: Record<string, unknown>
 * }} UiStepResult
 */

export class PopupProtocolStateMachine {
  /**
   * @param {'sender'|'receiver'} role
   * @param {{stepTimeoutMs?: number, sessionTtlMs?: number}} [options]
   */
  constructor(role, options = {}) {
    if (![ROLES.SENDER, ROLES.RECEIVER].includes(role)) {
      throw new Error(`Unknown role: ${role}`);
    }

    this.role = role;
    this.state = 'idle';
    this.sid = null;
    this.sessionCreatedAt = 0;
    this.stepDeadlineAt = 0;
    this.timer = null;

    this.stepTimeoutMs = options.stepTimeoutMs ?? DEFAULTS.stepTimeoutMs;
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULTS.sessionTtlMs;

    this.ctx = {
      params: null,
      local: null, // { algorithm, privateKey, publicKey, publicKeyB64 }
      remotePub: null,
      sharedSecret: null,
      aeadKeyBytes: null,
      saltB64: null
    };
  }

  dispose() {
    this._clearTimer();
    this._wipeSecrets();
    this.state = 'idle';
    this.sid = null;
  }

  _clearTimer() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  _startStepTimer() {
    this._clearTimer();

    this.stepDeadlineAt = nowMs() + this.stepTimeoutMs;
    this.timer = setTimeout(() => {
      this.state = 'expired';
      this._wipeSecrets();
      this.onStateChange?.({
        state: this.state,
        instruction:
          'Сессия истекла по таймауту. Начните заново: создайте новую одноразовую DH-сессию.'
      });
    }, this.stepTimeoutMs);
  }

  _ensureNotExpired() {
    if (!this.sid) return;
    if (nowMs() - this.sessionCreatedAt > this.sessionTtlMs) {
      this.state = 'expired';
      this._wipeSecrets();
      throw new Error('Сессия истекла (TTL). Запустите новую сессию.');
    }
  }

  _wipeSecrets() {
    this.ctx.local = null;
    this.ctx.remotePub = null;
    this.ctx.sharedSecret = null;
    this.ctx.aeadKeyBytes = null;
    // salt can stay in packet history, but clearing keeps behavior safer for popup memory.
    this.ctx.saltB64 = null;
  }

  _setState(state, instruction) {
    this.state = state;
    this._startStepTimer();
    const payload = { state, instruction };
    this.onStateChange?.(payload);
    return payload;
  }

  _setError(error) {
    this.state = 'error';
    this._clearTimer();
    this._wipeSecrets();
    const payload = {
      state: this.state,
      instruction:
        `Ошибка: ${error?.message || String(error)}. Проверьте шаги, затем начните новую сессию.`
    };
    this.onStateChange?.(payload);
    return payload;
  }

  /**
   * Sender: start from idle and produce params packet for MAX chat.
   * Transition: idle -> sent_params -> waiting_for_ack
   * @returns {Promise<UiStepResult>}
   */
  async startSender() {
    try {
      assert(this.role === ROLES.SENDER, 'startSender() доступен только для роли sender.');
      assert(this.state === 'idle', 'Сессию можно начать только из состояния idle.');

      this.sid = randomId();
      this.sessionCreatedAt = nowMs();

      const pair = await generateEphemeralKeyPair();
      const saltB64 = await generateHkdfSaltBase64();
      this.ctx.local = {
        algorithm: pair.algorithm,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
        publicKeyB64: await exportPublicKeyBase64(pair.publicKey, pair.algorithm)
      };
      this.ctx.saltB64 = saltB64;

      const params = makeEnvelope({
        type: 'params',
        sid: this.sid,
        from: 'A',
        to: 'B',
        body: {
          kex: pair.algorithm,
          kdf: 'HKDF-SHA-256',
          aead: 'AES-256-GCM',
          key_format: pair.algorithm === 'X25519' ? 'raw-base64' : 'spki-base64',
          ephemeral: true,
          single_message: true,
          ttl_sec: Math.floor(this.sessionTtlMs / 1000),
          salt: saltB64
        }
      });

      this.ctx.params = params;

      this.state = 'sent_params';
      this._setState(
        'waiting_for_ack',
        'Шаг 1/8 (Отправитель): отправьте JSON params в чат MAX и дождитесь ack_params от собеседника.'
      );

      return {
        state: this.state,
        instruction:
          'Скопируйте и отправьте в MAX: сообщение типа params. После получения ack_params вставьте его в расширение.',
        outgoing: JSON.stringify(params)
      };
    } catch (e) {
      return this._setError(e);
    }
  }

  /**
   * Receiver: process incoming `params`.
   * Transition: idle -> received_params -> ack_params_sent -> generated_priv
   * @param {string} rawJson
   * @returns {Promise<UiStepResult>}
   */
  async receiveParams(rawJson) {
    try {
      assert(this.role === ROLES.RECEIVER, 'receiveParams() доступен только для роли receiver.');
      assert(this.state === 'idle', 'Ожидался старт в состоянии idle.');

      const env = parseJsonSafe(rawJson);
      assert(env && env.type === 'params', 'Ожидалось сообщение типа params.');
      assert(env.proto === PROTO && env.ver === VERSION, 'Несовместимая версия/протокол.');
      assert(env.from === 'A' && env.to === 'B', 'Неверные роли в params.');

      this.sid = env.sid;
      this.sessionCreatedAt = nowMs();
      this.ctx.params = env;
      this.ctx.saltB64 = env.body?.salt;

      this._setState(
        'received_params',
        'Шаг 1/8 (Получатель): получены params. Подтвердите и отправьте ack_params в MAX.'
      );

      const ack = makeEnvelope({
        type: 'ack_params',
        sid: this.sid,
        from: 'B',
        to: 'A',
        body: {
          ack_msg_id: env.msg_id,
          accepted: true,
          selected: {
            kex: env.body.kex,
            kdf: env.body.kdf,
            aead: env.body.aead,
            key_format: env.body.key_format
          }
        }
      });

      this._setState(
        'ack_params_sent',
        'Шаг 2/8 (Получатель): отправьте ack_params в MAX. Далее сгенерируйте приватное значение и ждите pub от Отправителя.'
      );

      const pair = await generateEphemeralKeyPair();
      assert(pair.algorithm === env.body.kex, 'Локально недоступен согласованный kex-алгоритм.');

      this.ctx.local = {
        algorithm: pair.algorithm,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
        publicKeyB64: await exportPublicKeyBase64(pair.publicKey, pair.algorithm)
      };

      this._setState(
        'generated_priv',
        'Шаг 3/8 (Получатель): приватное значение сгенерировано. Вставьте pub от Отправителя, чтобы продолжить.'
      );

      return {
        state: this.state,
        instruction:
          'Скопируйте и отправьте в MAX: ack_params. Затем ожидайте pub от Отправителя и вставьте его в расширение.',
        outgoing: JSON.stringify(ack)
      };
    } catch (e) {
      return this._setError(e);
    }
  }

  /**
   * Sender: process incoming `ack_params` and produce local `pub`.
   * Transition: waiting_for_ack -> generated_priv -> sent_pub -> waiting_for_pub
   * @param {string} rawJson
   * @returns {Promise<UiStepResult>}
   */
  async senderHandleAckAndBuildPub(rawJson) {
    try {
      assert(this.role === ROLES.SENDER, 'Метод доступен только для sender.');
      assert(this.state === 'waiting_for_ack', 'Ожидалось состояние waiting_for_ack.');
      this._ensureNotExpired();

      const env = parseJsonSafe(rawJson);
      assert(env && env.type === 'ack_params', 'Ожидалось сообщение типа ack_params.');
      assert(env.sid === this.sid, 'sid не совпадает.');
      assert(env.body?.accepted === true, 'Параметры не подтверждены получателем.');
      assert(env.body?.selected?.kex === this.ctx.local?.algorithm, 'Алгоритм kex не совпадает с локальным выбором.');

      this._setState(
        'generated_priv',
        'Шаг 4/8 (Отправитель): приватное значение уже сгенерировано. Подготовьте и отправьте pub в MAX.'
      );

      const pub = makeEnvelope({
        type: 'pub',
        sid: this.sid,
        from: 'A',
        to: 'B',
        body: {
          kex: this.ctx.local.algorithm,
          pub: this.ctx.local.publicKeyB64,
          pub_format: this.ctx.local.algorithm === 'X25519' ? 'raw-base64' : 'spki-base64'
        }
      });

      this._setState(
        'sent_pub',
        'Шаг 5/8 (Отправитель): отправьте pub в MAX.'
      );

      this._setState(
        'waiting_for_pub',
        'Шаг 6/8 (Отправитель): дождитесь pub от Получателя и вставьте его в расширение.'
      );

      return {
        state: this.state,
        instruction: 'Скопируйте pub и отправьте в MAX. Затем дождитесь pub от Получателя.',
        outgoing: JSON.stringify(pub)
      };
    } catch (e) {
      return this._setError(e);
    }
  }

  /**
   * Receiver: process sender `pub`, compute secret, and produce own `pub`.
   * Transition: generated_priv -> received_pub -> sent_pub -> computed_secret -> waiting_for_ciphertext
   * @param {string} rawJson
   * @returns {Promise<UiStepResult>}
   */
  async receiverHandlePubAndReply(rawJson) {
    try {
      assert(this.role === ROLES.RECEIVER, 'Метод доступен только для receiver.');
      assert(this.state === 'generated_priv', 'Ожидалось состояние generated_priv.');
      this._ensureNotExpired();

      const env = parseJsonSafe(rawJson);
      assert(env && env.type === 'pub', 'Ожидалось сообщение типа pub.');
      assert(env.sid === this.sid, 'sid не совпадает.');
      assert(env.from === 'A' && env.to === 'B', 'Неверное направление pub.');

      this._setState('received_pub', 'Шаг 4/8 (Получатель): получен pub от Отправителя.');

      const remotePub = await importPublicKeyBase64(env.body.pub, this.ctx.local.algorithm);
      this.ctx.remotePub = remotePub;

      const shared = await deriveSharedSecret(this.ctx.local.privateKey, remotePub, this.ctx.local.algorithm);
      this.ctx.sharedSecret = shared;

      const saltBytes = await base64Decode(this.ctx.saltB64);
      const info = new TextEncoder().encode(`${PROTO}|v${VERSION}|sid:${this.sid}|A->B`);
      this.ctx.aeadKeyBytes = await deriveAeadKey(shared, saltBytes, info);

      const pubBack = makeEnvelope({
        type: 'pub',
        sid: this.sid,
        from: 'B',
        to: 'A',
        body: {
          kex: this.ctx.local.algorithm,
          pub: this.ctx.local.publicKeyB64,
          pub_format: this.ctx.local.algorithm === 'X25519' ? 'raw-base64' : 'spki-base64'
        }
      });

      this._setState('sent_pub', 'Шаг 5/8 (Получатель): отправьте ваш pub в MAX.');
      this._setState(
        'computed_secret',
        'Шаг 6/8 (Получатель): общий секрет вычислен, ключ шифрования готов.'
      );
      this._setState(
        'waiting_for_ciphertext',
        'Шаг 7/8 (Получатель): ожидайте ciphertext-пакет от Отправителя и вставьте его в расширение.'
      );

      return {
        state: this.state,
        instruction: 'Скопируйте pub и отправьте в MAX. После этого ожидайте ciphertext.',
        outgoing: JSON.stringify(pubBack)
      };
    } catch (e) {
      return this._setError(e);
    }
  }

  /**
   * Sender: process receiver pub, derive secret, encrypt plaintext and build final packet.
   * Transition: waiting_for_pub -> computed_secret -> encrypt_and_send
   * @param {string} rawJson
   * @param {string} plaintext
   * @returns {Promise<UiStepResult>}
   */
  async senderHandlePubEncrypt(rawJson, plaintext) {
    try {
      assert(this.role === ROLES.SENDER, 'Метод доступен только для sender.');
      assert(this.state === 'waiting_for_pub', 'Ожидалось состояние waiting_for_pub.');
      assert(typeof plaintext === 'string' && plaintext.length > 0, 'Нужен непустой plaintext.');
      this._ensureNotExpired();

      const env = parseJsonSafe(rawJson);
      assert(env && env.type === 'pub', 'Ожидалось сообщение типа pub.');
      assert(env.sid === this.sid, 'sid не совпадает.');
      assert(env.from === 'B' && env.to === 'A', 'Неверное направление pub.');

      const remotePub = await importPublicKeyBase64(env.body.pub, this.ctx.local.algorithm);
      this.ctx.remotePub = remotePub;

      const shared = await deriveSharedSecret(this.ctx.local.privateKey, remotePub, this.ctx.local.algorithm);
      this.ctx.sharedSecret = shared;

      const saltBytes = await base64Decode(this.ctx.saltB64);
      const info = new TextEncoder().encode(`${PROTO}|v${VERSION}|sid:${this.sid}|A->B`);
      this.ctx.aeadKeyBytes = await deriveAeadKey(shared, saltBytes, info);

      this._setState('computed_secret', 'Шаг 7/8 (Отправитель): общий секрет вычислен, можно шифровать.');

      const ts = nowMs();
      const aad = {
        sender_id: this.ctx.local.publicKeyB64,
        version: VERSION,
        ts
      };

      const encrypted = await encryptWithKey(this.ctx.aeadKeyBytes, plaintext, aad);
      const finalBlob = await buildFinalPacket(
        this.ctx.local.publicKeyB64,
        encrypted.iv,
        { ciphertext: encrypted.ciphertext, tag: encrypted.tag },
        this.ctx.saltB64,
        VERSION,
        ts
      );

      this._setState(
        'encrypt_and_send',
        'Шаг 8/8 (Отправитель): отправьте final packet (base64 JSON) в чат MAX.'
      );

      this._wipeSecrets(); // one-time session: wipe immediately after packet creation
      return {
        state: this.state,
        instruction:
          'Скопируйте final packet и отправьте в MAX. После отправки начните новую сессию для следующего сообщения.',
        outgoing: finalBlob,
        extra: { packetFormat: 'base64(json)' }
      };
    } catch (e) {
      return this._setError(e);
    }
  }

  /**
   * Receiver: parse final packet and decrypt.
   * Transition: waiting_for_ciphertext -> decrypt
   * @param {string} blob base64(json)
   * @returns {Promise<UiStepResult>}
   */
  async receiverDecryptFinalPacket(blob) {
    try {
      assert(this.role === ROLES.RECEIVER, 'Метод доступен только для receiver.');
      assert(this.state === 'waiting_for_ciphertext', 'Ожидалось состояние waiting_for_ciphertext.');
      this._ensureNotExpired();

      const packet = await parseFinalPacket(blob);
      assert(packet.version === VERSION, 'Неподдерживаемая версия пакета.');

      const aad = {
        sender_id: packet.sender_pub,
        version: packet.version,
        ts: packet.ts
      };

      const plaintext = await decryptWithKey(
        this.ctx.aeadKeyBytes,
        {
          iv: packet.iv,
          ciphertext: packet.ciphertext,
          tag: packet.tag
        },
        aad
      );

      this._setState('decrypt', 'Шаг 8/8 (Получатель): сообщение успешно расшифровано.');

      this._wipeSecrets(); // one-time session
      return {
        state: this.state,
        instruction: 'Расшифровка успешна. Для следующего сообщения начните новую сессию.',
        extra: { plaintext }
      };
    } catch (e) {
      return this._setError(e);
    }
  }
}
