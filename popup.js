import { PopupProtocolStateMachine, ROLES } from './state-machine.js';
import { generateHkdfSaltBase64 } from './cipher.js';
import { randomBytes, base64Encode } from './crypto.js';

const UI_STATE_KEY = 'maxdh_popup_ui_state_v2';

const $ = (id) => document.getElementById(id);

const els = {
  tabSend: $('tab-send'),
  tabRead: $('tab-read'),
  panelSend: document.querySelector('[data-panel="send"]'),
  panelRead: document.querySelector('[data-panel="read"]'),
  openStandalone: $('open-standalone'),
  globalStatus: $('global-status'),

  sendStep: $('send-step'),
  sendHint: $('send-hint'),
  sendStart: $('send-start'),
  sendReset: $('send-reset'),

  sendBlockCopyParams: $('send-block-copy-params'),
  sendBlockAck: $('send-block-ack'),
  sendBlockCopyPub: $('send-block-copy-pub'),
  sendBlockPeerPub: $('send-block-peer-pub'),
  sendBlockPlaintext: $('send-block-plaintext'),
  sendBlockFinal: $('send-block-final'),

  sendOutgoingParams: $('send-outgoing-params'),
  sendCopyParams: $('send-copy-params'),
  sendAckInput: $('send-ack-input'),
  sendApplyAck: $('send-apply-ack'),
  sendOutgoingPub: $('send-outgoing-pub'),
  sendCopyPub: $('send-copy-pub'),
  sendPeerPubInput: $('send-peer-pub-input'),
  sendPlaintext: $('send-plaintext'),
  sendEncrypt: $('send-encrypt'),
  sendOutgoingFinal: $('send-outgoing-final'),
  sendCopyFinal: $('send-copy-final'),

  readStep: $('read-step'),
  readHint: $('read-hint'),
  readReset: $('read-reset'),

  readBlockCopyAck: $('read-block-copy-ack'),
  readBlockPubInput: $('read-block-pub-input'),
  readBlockCopyPub: $('read-block-copy-pub'),
  readBlockCiphertext: $('read-block-ciphertext'),
  readBlockPlaintext: $('read-block-plaintext'),

  readParamsInput: $('read-params-input'),
  readApplyParams: $('read-apply-params'),
  readOutgoingAck: $('read-outgoing-ack'),
  readCopyAck: $('read-copy-ack'),
  readPeerPubInput: $('read-peer-pub-input'),
  readApplyPub: $('read-apply-pub'),
  readOutgoingPub: $('read-outgoing-pub'),
  readCopyPub: $('read-copy-pub'),
  readCiphertextInput: $('read-ciphertext-input'),
  readDecrypt: $('read-decrypt'),
  readPlaintext: $('read-plaintext')
};

const senderSM = new PopupProtocolStateMachine(ROLES.SENDER);
const receiverSM = new PopupProtocolStateMachine(ROLES.RECEIVER);

function setStatus(text) {
  els.globalStatus.textContent = text;
}

async function copyText(value) {
  if (!value) throw new Error('Нет данных для копирования.');
  await navigator.clipboard.writeText(value);
}

function setHidden(el, hidden) {
  el.classList.toggle('hidden', hidden);
}

function switchTab(tab) {
  const isSend = tab === 'send';
  els.tabSend.classList.toggle('is-active', isSend);
  els.tabRead.classList.toggle('is-active', !isSend);
  els.tabSend.setAttribute('aria-selected', String(isSend));
  els.tabRead.setAttribute('aria-selected', String(!isSend));
  els.panelSend.classList.toggle('hidden', !isSend);
  els.panelRead.classList.toggle('hidden', isSend);
  persistUiState();
}

function updateSenderBlocks() {
  const s = senderSM.state;

  setHidden(els.sendBlockCopyParams, !['waiting_for_ack', 'generated_priv', 'sent_pub', 'waiting_for_pub', 'computed_secret', 'encrypt_and_send'].includes(s));
  setHidden(els.sendBlockAck, s !== 'waiting_for_ack');
  setHidden(els.sendBlockCopyPub, !['waiting_for_pub', 'computed_secret', 'encrypt_and_send'].includes(s));
  setHidden(els.sendBlockPeerPub, s !== 'waiting_for_pub');
  setHidden(els.sendBlockPlaintext, !['waiting_for_pub'].includes(s));
  setHidden(els.sendBlockFinal, s !== 'encrypt_and_send');

  const hints = {
    idle: 'Нажмите «Новая сессия», затем отправьте params в MAX.',
    waiting_for_ack: 'Вставьте ack_params от собеседника и подтвердите.',
    waiting_for_pub: 'Сначала вставьте pub собеседника, затем введите plaintext и нажмите «Зашифровать».',
    encrypt_and_send: 'Скопируйте final packet и отправьте его в MAX.'
  };
  els.sendHint.textContent = hints[s] || 'Следуйте текущему шагу протокола.';
}

function updateReceiverBlocks() {
  const s = receiverSM.state;

  setHidden(els.readBlockCopyAck, !['generated_priv', 'received_pub', 'sent_pub', 'computed_secret', 'waiting_for_ciphertext', 'decrypt'].includes(s));
  setHidden(els.readBlockPubInput, s !== 'generated_priv');
  setHidden(els.readBlockCopyPub, !['waiting_for_ciphertext', 'decrypt'].includes(s));
  setHidden(els.readBlockCiphertext, s !== 'waiting_for_ciphertext');
  setHidden(els.readBlockPlaintext, s !== 'decrypt');

  const hints = {
    idle: 'Вставьте params от Отправителя и подтвердите.',
    generated_priv: 'Отправьте ack_params, затем вставьте pub Отправителя.',
    waiting_for_ciphertext: 'Отправьте свой pub в MAX и дождитесь final packet.',
    decrypt: 'Сообщение расшифровано. Для следующего сообщения начните новую сессию.'
  };
  els.readHint.textContent = hints[s] || 'Следуйте текущему шагу протокола.';
}

function renderStates() {
  els.sendStep.textContent = `Состояние: ${senderSM.state}`;
  els.readStep.textContent = `Состояние: ${receiverSM.state}`;
  updateSenderBlocks();
  updateReceiverBlocks();
}

async function saveOutgoingPayload(payload) {
  if (!payload) return;
  try {
    await chrome.storage.local.set({
      maxdh_last_outgoing_payload: payload,
      maxdh_last_outgoing_ts: Date.now()
    });
    await chrome.runtime.sendMessage({ type: 'MAXDH_SET_OUTGOING', payload });
  } catch {
    // ignore
  }
}

function collectUiState() {
  return {
    activeTab: els.panelSend.classList.contains('hidden') ? 'read' : 'send',
    sender: {
      outgoingParams: els.sendOutgoingParams.value,
      ackInput: els.sendAckInput.value,
      outgoingPub: els.sendOutgoingPub.value,
      peerPubInput: els.sendPeerPubInput.value,
      plaintext: els.sendPlaintext.value,
      outgoingFinal: els.sendOutgoingFinal.value
    },
    receiver: {
      paramsInput: els.readParamsInput.value,
      outgoingAck: els.readOutgoingAck.value,
      peerPubInput: els.readPeerPubInput.value,
      outgoingPub: els.readOutgoingPub.value,
      ciphertextInput: els.readCiphertextInput.value,
      plaintext: els.readPlaintext.value
    }
  };
}

async function persistUiState() {
  try {
    await chrome.storage.local.set({ [UI_STATE_KEY]: collectUiState() });
  } catch {
    // ignore
  }
}

async function restoreUiState() {
  try {
    const data = await chrome.storage.local.get(UI_STATE_KEY);
    const state = data?.[UI_STATE_KEY];
    if (!state) return;

    els.sendOutgoingParams.value = state.sender?.outgoingParams || '';
    els.sendAckInput.value = state.sender?.ackInput || '';
    els.sendOutgoingPub.value = state.sender?.outgoingPub || '';
    els.sendPeerPubInput.value = state.sender?.peerPubInput || '';
    els.sendPlaintext.value = state.sender?.plaintext || '';
    els.sendOutgoingFinal.value = state.sender?.outgoingFinal || '';

    els.readParamsInput.value = state.receiver?.paramsInput || '';
    els.readOutgoingAck.value = state.receiver?.outgoingAck || '';
    els.readPeerPubInput.value = state.receiver?.peerPubInput || '';
    els.readOutgoingPub.value = state.receiver?.outgoingPub || '';
    els.readCiphertextInput.value = state.receiver?.ciphertextInput || '';
    els.readPlaintext.value = state.receiver?.plaintext || '';

    switchTab(state.activeTab === 'read' ? 'read' : 'send');
    setStatus('Черновики восстановлены. Для продолжения крипто-сессии используйте режим «Открыть в отдельной вкладке».');
  } catch {
    // ignore
  }
}

function bindPersistenceInputs() {
  const ids = [
    'send-ack-input', 'send-peer-pub-input', 'send-plaintext',
    'read-params-input', 'read-peer-pub-input', 'read-ciphertext-input'
  ];
  ids.forEach((id) => $(id).addEventListener('input', persistUiState));
}

senderSM.onStateChange = ({ instruction }) => {
  renderStates();
  setStatus(instruction);
  persistUiState();
};

receiverSM.onStateChange = ({ instruction }) => {
  renderStates();
  setStatus(instruction);
  persistUiState();
};

async function senderStart() {
  try {
    const res = await senderSM.startSender();
    els.sendOutgoingParams.value = res.outgoing || '';
    await saveOutgoingPayload(els.sendOutgoingParams.value.trim());
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка: ${e.message}`);
  }
}

async function senderApplyAck() {
  try {
    const res = await senderSM.senderHandleAckAndBuildPub(els.sendAckInput.value.trim());
    els.sendOutgoingPub.value = res.outgoing || '';
    await saveOutgoingPayload(els.sendOutgoingPub.value.trim());
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка ack_params: ${e.message}`);
  }
}

async function senderEncrypt() {
  try {
    const res = await senderSM.senderHandlePubEncrypt(
      els.sendPeerPubInput.value.trim(),
      els.sendPlaintext.value
    );
    els.sendOutgoingFinal.value = res.outgoing || '';
    await saveOutgoingPayload(els.sendOutgoingFinal.value.trim());
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка шифрования: ${e.message}`);
  }
}

function resetSender() {
  senderSM.dispose();
  els.sendOutgoingParams.value = '';
  els.sendAckInput.value = '';
  els.sendOutgoingPub.value = '';
  els.sendPeerPubInput.value = '';
  els.sendPlaintext.value = '';
  els.sendOutgoingFinal.value = '';
  renderStates();
  setStatus('Сессия Отправителя сброшена.');
  persistUiState();
}

async function receiverApplyParams() {
  try {
    const res = await receiverSM.receiveParams(els.readParamsInput.value.trim());
    els.readOutgoingAck.value = res.outgoing || '';
    await saveOutgoingPayload(els.readOutgoingAck.value.trim());
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка params: ${e.message}`);
  }
}

async function receiverApplyPub() {
  try {
    const res = await receiverSM.receiverHandlePubAndReply(els.readPeerPubInput.value.trim());
    els.readOutgoingPub.value = res.outgoing || '';
    await saveOutgoingPayload(els.readOutgoingPub.value.trim());
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка pub: ${e.message}`);
  }
}

async function receiverDecrypt() {
  try {
    const res = await receiverSM.receiverDecryptFinalPacket(els.readCiphertextInput.value.trim());
    els.readPlaintext.value = String(res.extra?.plaintext || '');
    renderStates();
    await persistUiState();
  } catch (e) {
    setStatus(`Ошибка расшифровки: ${e.message}`);
  }
}

function resetReceiver() {
  receiverSM.dispose();
  els.readParamsInput.value = '';
  els.readOutgoingAck.value = '';
  els.readPeerPubInput.value = '';
  els.readOutgoingPub.value = '';
  els.readCiphertextInput.value = '';
  els.readPlaintext.value = '';
  renderStates();
  setStatus('Сессия Получателя сброшена.');
  persistUiState();
}

els.tabSend.addEventListener('click', () => switchTab('send'));
els.tabRead.addEventListener('click', () => switchTab('read'));

els.openStandalone.addEventListener('click', () => {
  const url = chrome.runtime.getURL('popup.html?standalone=1');
  window.open(url, '_blank', 'noopener,noreferrer');
});

els.sendStart.addEventListener('click', senderStart);
els.sendApplyAck.addEventListener('click', senderApplyAck);
els.sendEncrypt.addEventListener('click', senderEncrypt);
els.sendReset.addEventListener('click', resetSender);

els.readApplyParams.addEventListener('click', receiverApplyParams);
els.readApplyPub.addEventListener('click', receiverApplyPub);
els.readDecrypt.addEventListener('click', receiverDecrypt);
els.readReset.addEventListener('click', resetReceiver);

els.sendCopyParams.addEventListener('click', async () => {
  await copyText(els.sendOutgoingParams.value.trim());
  setStatus('params скопирован. Вставьте в MAX.');
});
els.sendCopyPub.addEventListener('click', async () => {
  await copyText(els.sendOutgoingPub.value.trim());
  setStatus('pub скопирован. Вставьте в MAX.');
});
els.sendCopyFinal.addEventListener('click', async () => {
  await copyText(els.sendOutgoingFinal.value.trim());
  setStatus('final packet скопирован. Вставьте в MAX.');
});

els.readCopyAck.addEventListener('click', async () => {
  await copyText(els.readOutgoingAck.value.trim());
  setStatus('ack_params скопирован. Вставьте в MAX.');
});
els.readCopyPub.addEventListener('click', async () => {
  await copyText(els.readOutgoingPub.value.trim());
  setStatus('pub скопирован. Вставьте в MAX.');
});

chrome.runtime?.onMessage?.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'MAXDH_IMPORT_PAYLOAD') {
    const payload = String(msg.payload || '').trim();

    if (!els.panelSend.classList.contains('hidden')) {
      if (senderSM.state === 'waiting_for_ack') {
        els.sendAckInput.value = payload;
      } else if (senderSM.state === 'waiting_for_pub') {
        els.sendPeerPubInput.value = payload;
      }
    } else {
      if (receiverSM.state === 'idle') {
        els.readParamsInput.value = payload;
      } else if (receiverSM.state === 'generated_priv') {
        els.readPeerPubInput.value = payload;
      } else if (receiverSM.state === 'waiting_for_ciphertext') {
        els.readCiphertextInput.value = payload;
      }
    }

    persistUiState();
    setStatus('Данные импортированы из MAX. Проверьте шаг и нажмите нужную кнопку.');
    sendResponse?.({ ok: true });
    return true;
  }

  if (msg?.type === 'MAXDH_GET_OUTGOING') {
    const payload = !els.panelSend.classList.contains('hidden')
      ? (els.sendOutgoingFinal.value || els.sendOutgoingPub.value || els.sendOutgoingParams.value).trim()
      : (els.readOutgoingPub.value || els.readOutgoingAck.value).trim();

    sendResponse?.({ ok: true, payload });
    return true;
  }

  return false;
});

window.addEventListener('beforeunload', () => {
  // We keep UI drafts in storage for convenience.
  // Crypto session internals remain in memory only (and are lost on close by design).
  senderSM.dispose();
  receiverSM.dispose();
});

(async () => {
  renderStates();
  bindPersistenceInputs();
  await restoreUiState();

  try {
    const probe = await randomBytes(8);
    const probeB64 = await base64Encode(probe);
    const salt = await generateHkdfSaltBase64();
    setStatus(`Готово. Crypto OK (${probeB64.length}b64), salt=${salt.length}.`);
  } catch (e) {
    setStatus(`Инициализация crypto/cipher не удалась: ${e.message}`);
  }
})();
