/**
 * content-script.js
 *
 * MAX DOM integration with minimal intrusive behavior:
 * - Detect service messages (`maxdh:` prefix or protocol JSON payloads)
 * - Add "Импортировать в расширение" button per detected message
 * - Add "Сформировать сообщение" button near message composer
 *
 * Notes on selectors:
 * - We use a small fallback selector set to avoid hard-coding a fragile MAX layout.
 * - We mark processed nodes with data attributes to avoid repeated patching.
 * - We only append small buttons and never rewrite existing message text/content.
 */

const SERVICE_PREFIX = 'maxdh:';
const BTN_IMPORT_CLASS = 'maxdh-import-btn';
const BTN_COMPOSE_CLASS = 'maxdh-compose-btn';
const DATA_MARK_MESSAGE = 'maxdhBound';
const DATA_MARK_COMPOSER = 'maxdhComposerBound';

const MESSAGE_NODE_SELECTORS = [
  '[data-message-id]',
  '[role="listitem"]',
  '.message',
  '.msg'
].join(',');

const MESSAGE_TEXT_SELECTORS = [
  '[data-testid="message-text"]',
  '.message-text',
  '.text',
  '[dir="auto"]'
].join(',');

const COMPOSER_SELECTORS = [
  'textarea',
  '[contenteditable="true"][role="textbox"]',
  '[contenteditable="true"]'
].join(',');

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function normalizePayloadText(raw) {
  if (!raw) return '';
  let text = String(raw).trim();

  if (text.startsWith(SERVICE_PREFIX)) {
    text = text.slice(SERVICE_PREFIX.length).trim();
  }

  // Optional support for fenced blocks pasted in chats.
  text = text.replace(/^```json\s*/i, '').replace(/```$/i, '').trim();
  return text;
}

function isLikelyProtocolJson(obj) {
  if (!obj || typeof obj !== 'object') return false;
  const hasVersion = Number.isInteger(obj.ver) || Number.isInteger(obj.version);
  const hasType = typeof obj.type === 'string';
  const hasProto = typeof obj.proto === 'string' || obj.proto === undefined;
  return hasVersion && hasType && hasProto;
}

function extractMessageText(messageEl) {
  const textEl = messageEl.querySelector(MESSAGE_TEXT_SELECTORS);
  const raw = (textEl?.innerText ?? messageEl.innerText ?? '').trim();
  return raw;
}

function getServicePayloadFromMessage(messageEl) {
  const raw = extractMessageText(messageEl);
  if (!raw) return null;

  if (raw.startsWith(SERVICE_PREFIX)) {
    const payload = normalizePayloadText(raw);
    const obj = safeJsonParse(payload);
    return obj ? payload : null;
  }

  // Whole-message JSON fallback
  const normalized = normalizePayloadText(raw);
  const wholeObj = safeJsonParse(normalized);
  if (isLikelyProtocolJson(wholeObj)) return normalized;

  return null;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

async function pushPayloadToExtension(payload) {
  // 1) Try runtime message (popup/background can consume).
  try {
    await chrome.runtime.sendMessage({ type: 'MAXDH_IMPORT_PAYLOAD', payload });
  } catch {
    // ignore, popup may be closed.
  }

  // 2) Store latest payload as fallback for popup to pick up.
  try {
    await chrome.storage.local.set({ maxdh_last_import_payload: payload, maxdh_last_import_ts: Date.now() });
  } catch {
    // ignore storage failures
  }
}

function buildImportButton(payload) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = BTN_IMPORT_CLASS;
  btn.textContent = 'Импортировать в расширение';
  btn.style.marginLeft = '8px';
  btn.style.fontSize = '12px';
  btn.style.padding = '2px 6px';
  btn.style.cursor = 'pointer';

  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    await pushPayloadToExtension(payload);
    const copied = await copyToClipboard(payload);
    btn.textContent = copied ? 'Импортировано ✓' : 'Импортировано';
    setTimeout(() => {
      btn.textContent = 'Импортировать в расширение';
    }, 1200);
  });

  return btn;
}

function patchMessageNode(messageEl) {
  if (!messageEl || messageEl.dataset[DATA_MARK_MESSAGE] === '1') return;

  const payload = getServicePayloadFromMessage(messageEl);
  if (!payload) return;

  // Mark first to avoid duplicate injection.
  messageEl.dataset[DATA_MARK_MESSAGE] = '1';

  const anchor = messageEl.querySelector(MESSAGE_TEXT_SELECTORS) || messageEl;
  const btn = buildImportButton(payload);
  anchor.appendChild(btn);
}

function insertTextToComposer(composerEl, text) {
  if (!composerEl) return;

  if (composerEl.tagName === 'TEXTAREA' || composerEl.tagName === 'INPUT') {
    composerEl.focus();
    composerEl.value = text;
    composerEl.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }

  composerEl.focus();
  composerEl.textContent = text;
  composerEl.dispatchEvent(new InputEvent('input', { bubbles: true }));
}

function buildComposeButton(composerEl) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = BTN_COMPOSE_CLASS;
  btn.textContent = 'Сформировать сообщение';
  btn.style.marginLeft = '8px';
  btn.style.fontSize = '12px';
  btn.style.padding = '4px 8px';
  btn.style.cursor = 'pointer';

  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    let payload = '';

    // Prefer runtime request (if popup/background exposes latest outgoing).
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'MAXDH_GET_OUTGOING' });
      payload = resp?.payload || '';
    } catch {
      // ignore and fallback to storage
    }

    // Fallback to last imported/outgoing values in storage.
    if (!payload) {
      try {
        const data = await chrome.storage.local.get(['maxdh_last_outgoing_payload', 'maxdh_last_import_payload']);
        payload = data.maxdh_last_outgoing_payload || data.maxdh_last_import_payload || '';
      } catch {
        // ignore
      }
    }

    if (!payload) {
      btn.textContent = 'Нет данных';
      setTimeout(() => (btn.textContent = 'Сформировать сообщение'), 1200);
      return;
    }

    insertTextToComposer(composerEl, payload.startsWith(SERVICE_PREFIX) ? payload : `${SERVICE_PREFIX} ${payload}`);
    btn.textContent = 'Вставлено ✓';
    setTimeout(() => (btn.textContent = 'Сформировать сообщение'), 1200);
  });

  return btn;
}

function patchComposer() {
  const composerEl = document.querySelector(COMPOSER_SELECTORS);
  if (!composerEl) return;
  if (composerEl.dataset[DATA_MARK_COMPOSER] === '1') return;

  composerEl.dataset[DATA_MARK_COMPOSER] = '1';

  const btn = buildComposeButton(composerEl);

  // Minimal DOM touch: inject one sibling button next to composer.
  const parent = composerEl.parentElement;
  if (!parent) return;

  const wrapper = document.createElement('div');
  wrapper.style.display = 'flex';
  wrapper.style.alignItems = 'center';
  wrapper.style.marginTop = '6px';
  wrapper.appendChild(btn);

  parent.appendChild(wrapper);
}

function scanAndPatch() {
  const messageNodes = document.querySelectorAll(MESSAGE_NODE_SELECTORS);
  messageNodes.forEach((el) => patchMessageNode(el));
  patchComposer();
}

function initObserver() {
  scanAndPatch();

  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const m of mutations) {
      if (m.type === 'childList' && (m.addedNodes?.length || m.removedNodes?.length)) {
        shouldScan = true;
        break;
      }
      if (m.type === 'characterData') {
        shouldScan = true;
        break;
      }
    }

    if (shouldScan) {
      scanAndPatch();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true
  });
}

initObserver();
