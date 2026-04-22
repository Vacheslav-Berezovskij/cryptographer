import { PopupProtocolStateMachine, ROLES } from './state-machine.js';
import { generateHkdfSaltBase64 } from './cipher.js';
import { randomBytes, base64Encode } from './crypto.js';

const $ = (id) => document.getElementById(id);

const els = {
  tabSend: $('tab-send'),
  tabRead: $('tab-read'),
  panelSend: document.querySelector('[data-panel="send"]'),
  panelRead: document.querySelector('[data-panel="read"]'),
  globalStatus: $('global-status'),

  sendStep: $('send-step'),
  sendPlaintext: $('send-plaintext'),
  sendIncoming: $('send-incoming'),
  sendOutgoing: $('send-outgoing'),
  sendStart: $('send-start'),
  sendNext: $('send-next'),
  sendCopy: $('send-copy'),
  sendReset: $('send-reset'),

  readStep: $('read-step'),
  readIncoming: $('read-incoming'),
  readOutgoing: $('read-outgoing'),
  readPlaintext: $('read-plaintext'),
  readNext: $('read-next'),
  readCopy: $('read-copy'),
  readReset: $('read-reset')
};

const senderSM = new PopupProtocolStateMachine(ROLES.SENDER);
const receiverSM = new PopupProtocolStateMachine(ROLES.RECEIVER);

senderSM.onStateChange = ({ state, instruction }) => {
  els.sendStep.textContent = `Состояние: ${state}`;
  setStatus(instruction);
};

receiverSM.onStateChange = ({ state, instruction }) => {
  els.readStep.textContent = `Состояние: ${state}`;
  setStatus(instruction);
};

function setStatus(text) {
  els.globalStatus.textContent = text;
}

function switchTab(tab) {
  const isSend = tab === 'send';
  els.tabSend.classList.toggle('is-active', isSend);
  els.tabRead.classList.toggle('is-active', !isSend);
  els.tabSend.setAttribute('aria-selected', String(isSend));
  els.tabRead.setAttribute('aria-selected', String(!isSend));
  els.panelSend.classList.toggle('hidden', !isSend);
  els.panelRead.classList.toggle('hidden', isSend);
}

async function copyText(value) {
  if (!value) throw new Error('Нет данных для копирования.');
  await navigator.clipboard.writeText(value);
}

function looksLikeJson(raw) {
  const t = (raw || '').trim();
  return t.startsWith('{') && t.endsWith('}');
}

async function handleSenderNext() {
  try {
    const state = senderSM.state;
    const incoming = els.sendIncoming.value.trim();

    if (state === 'idle') {
      const res = await senderSM.startSender();
      els.sendOutgoing.value = res.outgoing ?? '';
      return;
    }

    if (state === 'waiting_for_ack') {
      if (!looksLikeJson(incoming)) throw new Error('Вставьте JSON ack_params от Получателя.');
      const res = await senderSM.senderHandleAckAndBuildPub(incoming);
      els.sendOutgoing.value = res.outgoing ?? '';
      return;
    }

    if (state === 'waiting_for_pub') {
      if (!looksLikeJson(incoming)) throw new Error('Вставьте JSON pub от Получателя.');
      const plaintext = els.sendPlaintext.value;
      const res = await senderSM.senderHandlePubEncrypt(incoming, plaintext);
      els.sendOutgoing.value = res.outgoing ?? '';
      return;
    }

    if (state === 'encrypt_and_send') {
      setStatus('Пакет готов. Отправьте его в MAX и начните новую сессию для следующего сообщения.');
      return;
    }

    throw new Error(`Для состояния ${state} нет действия "Следующий шаг".`);
  } catch (err) {
    setStatus(`Ошибка (Отправитель): ${err.message}`);
  }
}

async function handleReceiverNext() {
  try {
    const state = receiverSM.state;
    const incoming = els.readIncoming.value.trim();

    if (state === 'idle') {
      if (!looksLikeJson(incoming)) throw new Error('Вставьте JSON params от Отправителя.');
      const res = await receiverSM.receiveParams(incoming);
      els.readOutgoing.value = res.outgoing ?? '';
      return;
    }

    if (state === 'generated_priv') {
      if (!looksLikeJson(incoming)) throw new Error('Вставьте JSON pub от Отправителя.');
      const res = await receiverSM.receiverHandlePubAndReply(incoming);
      els.readOutgoing.value = res.outgoing ?? '';
      return;
    }

    if (state === 'waiting_for_ciphertext') {
      const res = await receiverSM.receiverDecryptFinalPacket(incoming);
      els.readPlaintext.value = String(res.extra?.plaintext ?? '');
      return;
    }

    if (state === 'decrypt') {
      setStatus('Сообщение уже расшифровано. Для следующего — сбросьте и начните новую сессию.');
      return;
    }

    throw new Error(`Для состояния ${state} нет действия "Следующий шаг".`);
  } catch (err) {
    setStatus(`Ошибка (Получатель): ${err.message}`);
  }
}

/**
 * Auto-parse helper:
 * - Sender: when ack/pub pasted, we can auto-advance.
 * - Receiver: when params/pub/ciphertext pasted, we can auto-advance.
 */
let senderPasteTimer = null;
let receiverPasteTimer = null;

function debounce(fn, delay, key) {
  if (key === 'sender') {
    if (senderPasteTimer) clearTimeout(senderPasteTimer);
    senderPasteTimer = setTimeout(fn, delay);
    return;
  }
  if (receiverPasteTimer) clearTimeout(receiverPasteTimer);
  receiverPasteTimer = setTimeout(fn, delay);
}

els.sendIncoming.addEventListener('input', () => {
  debounce(async () => {
    const raw = els.sendIncoming.value.trim();
    if (!raw) return;
    if (!looksLikeJson(raw)) return;

    // Auto-suggest only in states where incoming JSON is expected.
    if (['waiting_for_ack', 'waiting_for_pub'].includes(senderSM.state)) {
      setStatus('Обнаружен валидный JSON. Нажмите "Следующий шаг" для продолжения.');
    }
  }, 200, 'sender');
});

els.readIncoming.addEventListener('input', () => {
  debounce(async () => {
    const raw = els.readIncoming.value.trim();
    if (!raw) return;

    if (receiverSM.state === 'waiting_for_ciphertext' && !looksLikeJson(raw)) {
      setStatus('Похоже на final packet (base64). Нажмите "Следующий шаг" для расшифровки.');
      return;
    }

    if (looksLikeJson(raw) && ['idle', 'generated_priv'].includes(receiverSM.state)) {
      setStatus('Обнаружен JSON для текущего шага. Нажмите "Следующий шаг".');
    }
  }, 200, 'receiver');
});

els.sendStart.addEventListener('click', async () => {
  try {
    const res = await senderSM.startSender();
    els.sendOutgoing.value = res.outgoing ?? '';
  } catch (err) {
    setStatus(`Ошибка запуска отправителя: ${err.message}`);
  }
});

els.sendNext.addEventListener('click', handleSenderNext);
els.readNext.addEventListener('click', handleReceiverNext);

els.sendCopy.addEventListener('click', async () => {
  try {
    await copyText(els.sendOutgoing.value.trim());
    setStatus('Исходящее сообщение Отправителя скопировано. Вставьте его в MAX.');
  } catch (err) {
    setStatus(`Ошибка копирования: ${err.message}`);
  }
});

els.readCopy.addEventListener('click', async () => {
  try {
    await copyText(els.readOutgoing.value.trim());
    setStatus('Исходящее сообщение Получателя скопировано. Вставьте его в MAX.');
  } catch (err) {
    setStatus(`Ошибка копирования: ${err.message}`);
  }
});

function resetSender() {
  senderSM.dispose();
  els.sendStep.textContent = 'Состояние: idle';
  els.sendIncoming.value = '';
  els.sendOutgoing.value = '';
  els.sendPlaintext.value = '';
  setStatus('Сессия Отправителя сброшена. Секреты очищены из памяти popup.');
}

function resetReceiver() {
  receiverSM.dispose();
  els.readStep.textContent = 'Состояние: idle';
  els.readIncoming.value = '';
  els.readOutgoing.value = '';
  els.readPlaintext.value = '';
  setStatus('Сессия Получателя сброшена. Секреты очищены из памяти popup.');
}

els.sendReset.addEventListener('click', resetSender);
els.readReset.addEventListener('click', resetReceiver);

els.tabSend.addEventListener('click', () => switchTab('send'));
els.tabRead.addEventListener('click', () => switchTab('read'));

// Safety: cleanup ephemeral states when popup closes/reloads.
window.addEventListener('beforeunload', () => {
  senderSM.dispose();
  receiverSM.dispose();
});

// Lightweight runtime self-check that touches crypto/cipher modules explicitly.
(async () => {
  try {
    const probe = await randomBytes(8);
    const probeB64 = await base64Encode(probe);
    const salt = await generateHkdfSaltBase64();
    setStatus(`Готово. Crypto OK (${probeB64.length}b64), HKDF salt ready (${salt.length} chars).`);
  } catch (e) {
    setStatus(`Инициализация crypto/cipher не удалась: ${e.message}`);
  }
})();
