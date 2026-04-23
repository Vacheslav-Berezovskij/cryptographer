/**
 * background.js (MV3 service worker)
 *
 * Responsibilities:
 * - Central bridge between content script and popup.
 * - Keeps only short-lived payload buffers in memory/storage for UX convenience.
 * - No network calls, no external services.
 */

const KEY_LAST_IMPORT = 'maxdh_last_import_payload';
const KEY_LAST_OUTGOING = 'maxdh_last_outgoing_payload';

/**
 * Save a payload as the latest outgoing message.
 * Popup can call this to expose generated JSON/blob to content-script.
 */
async function setOutgoingPayload(payload) {
  if (!payload) return;
  await chrome.storage.local.set({
    [KEY_LAST_OUTGOING]: payload,
    maxdh_last_outgoing_ts: Date.now()
  });
}

/**
 * Save imported payload from MAX page.
 */
async function setImportPayload(payload) {
  if (!payload) return;
  await chrome.storage.local.set({
    [KEY_LAST_IMPORT]: payload,
    maxdh_last_import_ts: Date.now()
  });
}

/**
 * Return latest payload with fallback order:
 * 1) outgoing payload (preferred for "Сформировать сообщение")
 * 2) imported payload
 */
async function getBestPayload() {
  const data = await chrome.storage.local.get([KEY_LAST_OUTGOING, KEY_LAST_IMPORT]);
  return data[KEY_LAST_OUTGOING] || data[KEY_LAST_IMPORT] || '';
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === 'MAXDH_IMPORT_PAYLOAD') {
        await setImportPayload(String(msg.payload || ''));
        sendResponse({ ok: true });
        return;
      }

      if (msg?.type === 'MAXDH_SET_OUTGOING') {
        await setOutgoingPayload(String(msg.payload || ''));
        sendResponse({ ok: true });
        return;
      }

      if (msg?.type === 'MAXDH_GET_OUTGOING') {
        const payload = await getBestPayload();
        sendResponse({ ok: true, payload });
        return;
      }

      sendResponse({ ok: false, error: 'Unknown message type' });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});
