"use strict";

const V = 2;
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_PLAINTEXT_BYTES = 32 * 1024;
const MAX_FIELD_B64 = 96 * 1024;
const MAX_PEERS = 500;
const MAX_KNOWN_PEERS = 500;
const MAX_CONVERSATIONS = 100;
const MAX_MESSAGES_PER_CONVERSATION = 500;
const MAX_SEEN_MESSAGES = 4096;
const MAX_PACKET_QUEUE = 100;
const OAEP_LABEL = new TextEncoder().encode("ZTCHAT/v2/AES-GCM");
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const nicknamePattern = /^[A-Za-z0-9][A-Za-z0-9_. -]{0,31}$/;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const state = {
  db: null, identity: null, nickname: "", url: "", socket: null, authenticated: false,
  manuallyClosed: false, reconnectAttempts: 0, reconnectTimer: null,
  peers: new Map(), activePeerId: null, conversations: new Map(), packetQueue: Promise.resolve(),
  queueDepth: 0, incomingTokens: 60, incomingUpdated: performance.now(), floodNotified: false,
  seen: new Set(), toastTimer: null,
};

const ui = {
  onboarding: document.getElementById("onboarding"),
  chatApp: document.getElementById("chat-app"),
  connectForm: document.getElementById("connect-form"),
  nickname: document.getElementById("nickname"),
  relayUrl: document.getElementById("relay-url"),
  connectButton: document.getElementById("connect-button"),
  note: document.getElementById("connection-note"),
  selfName: document.getElementById("self-name"),
  selfId: document.getElementById("self-id"),
  presence: document.getElementById("presence"),
  peerFilter: document.getElementById("peer-filter"),
  peerList: document.getElementById("peer-list"),
  refreshPeers: document.getElementById("refresh-peers"),
  disconnect: document.getElementById("disconnect"),
  backToPeers: document.getElementById("back-to-peers"),
  conversationName: document.getElementById("conversation-name"),
  conversationId: document.getElementById("conversation-id"),
  securityChip: document.getElementById("security-chip"),
  messages: document.getElementById("messages"),
  verifyBanner: document.getElementById("verify-banner"),
  verifyPeer: document.getElementById("verify-peer"),
  composer: document.getElementById("composer"),
  input: document.getElementById("message-input"),
  sendButton: document.getElementById("send-button"),
  verifyDialog: document.getElementById("verify-dialog"),
  fingerprints: document.getElementById("fingerprints"),
  verifyConfirmation: document.getElementById("verify-confirmation"),
  cancelVerify: document.getElementById("cancel-verify"),
  confirmVerify: document.getElementById("confirm-verify"),
  toast: document.getElementById("toast"),
};

function bytesToB64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let start = 0; start < bytes.length; start += 8192) {
    binary += String.fromCharCode(...bytes.subarray(start, start + 8192));
  }
  return btoa(binary);
}

function b64ToBytes(value, expectedLength) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_B64) {
    throw new Error("Invalid base64 field.");
  }
  if (value.length % 4 !== 0 || !base64Pattern.test(value)) {
    throw new Error("Invalid base64 field.");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error("Invalid base64 field.");
  }
  const result = Uint8Array.from(binary, char => char.charCodeAt(0));
  // atob accepts several non-canonical spellings; reject them before using
  // message IDs as replay-cache keys.
  if (bytesToB64(result) !== value) throw new Error("Non-canonical base64 field.");
  if (expectedLength !== undefined && result.length !== expectedLength) throw new Error("Unexpected field length.");
  return result;
}

function b64urlToBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid key encoding.");
  const remainder = value.length % 4;
  if (remainder === 1) throw new Error("Invalid key encoding.");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + (remainder === 2 ? "==" : remainder === 3 ? "=" : "");
  return b64ToBytes(padded);
}

function hex(bytes) {
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
}

function idBytes(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("Invalid identity ID.");
  return Uint8Array.from(value.match(/.{2}/g), pair => parseInt(pair, 16));
}

function concat(...parts) {
  const arrays = parts.map(part => part instanceof Uint8Array ? part : new Uint8Array(part));
  const result = new Uint8Array(arrays.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of arrays) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function fingerprint(value) {
  const digest = await sha256(value);
  return Array.from(digest.slice(0, 16), item => item.toString(16).padStart(2, "0").toUpperCase())
    .join("").match(/.{1,4}/g).join(":");
}

function identifyData(challenge, identityId, nickname, signingHash, encryptionHash) {
  return concat(
    encoder.encode("ZTCHAT/v2/identify\0"), challenge, idBytes(identityId), encoder.encode(nickname),
    // The following hashes make the signed identity packet unambiguous.
    signingHash, encryptionHash,
  );
}

function messageAad(messageId, senderId, recipientId) {
  return concat(encoder.encode("ZTCHAT/v2/message-aad\0"), messageId, idBytes(senderId), idBytes(recipientId));
}

function signatureData(messageId, senderId, recipientId, wrappedKeyHash, nonce, ciphertextHash) {
  return concat(
    encoder.encode("ZTCHAT/v2/message-signature\0"),
    messageAad(messageId, senderId, recipientId),
    wrappedKeyHash, nonce, ciphertextHash,
  );
}

function randomBytes(length) {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

function idbRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function openIdentityDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("cipherwire-v2", 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("identity")) request.result.createObjectStore("identity");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGet(key) {
  const transaction = state.db.transaction("identity", "readonly");
  return idbRequest(transaction.objectStore("identity").get(key));
}

async function dbPut(key, value) {
  const transaction = state.db.transaction("identity", "readwrite");
  await idbRequest(transaction.objectStore("identity").put(value, key));
}

async function createIdentity() {
  const signing = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    false, ["sign", "verify"],
  );
  const encryption = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    false, ["encrypt", "decrypt"],
  );
  const signingDer = new Uint8Array(await crypto.subtle.exportKey("spki", signing.publicKey));
  const encryptionDer = new Uint8Array(await crypto.subtle.exportKey("spki", encryption.publicKey));
  if (hex(signingDer) === hex(encryptionDer)) throw new Error("Generated keys must be distinct.");
  const identity = {
    signingPrivate: signing.privateKey, signingPublic: signing.publicKey,
    encryptionPrivate: encryption.privateKey, encryptionPublic: encryption.publicKey,
    signingDer: bytesToB64(signingDer), encryptionDer: bytesToB64(encryptionDer),
  };
  await dbPut("keys", identity);
  return identity;
}

async function loadIdentity() {
  const record = await dbGet("keys") || await createIdentity();
  if (!record || typeof record.signingDer !== "string" || typeof record.encryptionDer !== "string") {
    throw new Error("Stored identity is invalid.");
  }
  const signingDer = b64ToBytes(record.signingDer);
  const encryptionDer = b64ToBytes(record.encryptionDer);
  if (hex(signingDer) === hex(encryptionDer)) throw new Error("Stored identity keys are not distinct.");
  const signingHash = await sha256(signingDer);
  const encryptionHash = await sha256(encryptionDer);
  return {
    signingPrivate: record.signingPrivate, signingPublic: record.signingPublic,
    encryptionPrivate: record.encryptionPrivate, encryptionPublic: record.encryptionPublic,
    signingDer, encryptionDer, signingHash, encryptionHash, identityId: hex(signingHash),
  };
}

function storageGet(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function knownPeersKey() {
  return "cipherwire-v2.known-peers." + state.identity.identityId;
}

function readKnownPeers() {
  try {
    const result = JSON.parse(storageGet(knownPeersKey()) || "{}");
    return result && typeof result === "object" && !Array.isArray(result) ? result : {};
  } catch {
    return {};
  }
}

function writeKnownPeers(value) {
  return storageSet(knownPeersKey(), JSON.stringify(value));
}

function seenMessagesKey() {
  return "cipherwire-v2.seen." + state.identity.identityId;
}

function loadSeenMessages() {
  state.seen = new Set();
  try {
    const values = JSON.parse(storageGet(seenMessagesKey()) || "[]");
    if (!Array.isArray(values)) return;
    for (const value of values.slice(-MAX_SEEN_MESSAGES)) {
      if (typeof value !== "string") continue;
      if (/^[0-9a-f]{32}$/.test(value)) {
        state.seen.add(value);
        continue;
      }
      // Migrate values written by older builds, which stored base64 text.
      try {
        state.seen.add(hex(b64ToBytes(value, 16)));
      } catch {
        // Ignore corrupt entries rather than disabling replay protection.
      }
    }
  } catch {
    state.seen = new Set();
  }
}

function markMessageSeen(messageIdHex) {
  state.seen.add(messageIdHex);
  while (state.seen.size > MAX_SEEN_MESSAGES) state.seen.delete(state.seen.values().next().value);
  if (!storageSet(seenMessagesKey(), JSON.stringify(Array.from(state.seen)))) {
    toast("Replay cache could not be saved; this session is still protected.");
  }
}

function normalizeUrl(value) {
  const url = new URL(value);
  if (url.username || url.password) throw new Error("Relay URLs must not contain credentials.");
  const local = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if (url.protocol === "wss:") return url.href;
  if (url.protocol === "ws:" && local) return url.href;
  throw new Error("Use a wss:// relay URL. ws:// is permitted only for localhost development.");
}

function setConnectionNote(text, isError) {
  ui.note.textContent = text;
  ui.note.classList.toggle("error", Boolean(isError));
}

function setPresence(connected, text) {
  ui.presence.textContent = text;
  ui.presence.classList.toggle("connected", connected);
}

function toast(text) {
  ui.toast.textContent = text;
  ui.toast.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => ui.toast.classList.remove("show"), 4500);
}

function peerInitial(name) {
  return (name || "?").trim().slice(0, 1).toUpperCase() || "?";
}

function selectedPeer() {
  return state.activePeerId ? state.peers.get(state.activePeerId) : null;
}

function formatTime() {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date());
}

function addConversationMessage(peerId, direction, text) {
  if (!state.conversations.has(peerId) && state.conversations.size >= MAX_CONVERSATIONS) {
    const oldest = state.conversations.keys().next().value;
    state.conversations.delete(oldest);
  }
  const messages = state.conversations.get(peerId) || [];
  messages.push({ direction, text, time: formatTime() });
  if (messages.length > MAX_MESSAGES_PER_CONVERSATION) messages.splice(0, messages.length - MAX_MESSAGES_PER_CONVERSATION);
  state.conversations.set(peerId, messages);
  if (state.activePeerId === peerId) renderMessages();
}

function renderMessages() {
  ui.messages.replaceChildren();
  const peer = selectedPeer();
  if (!peer) {
    const welcome = document.createElement("div");
    welcome.className = "welcome";
    const strong = document.createElement("strong");
    strong.textContent = "Start carefully.";
    welcome.append(strong, document.createTextNode("Select an online identity. New identities must be verified through another trusted channel before messages can be sent."));
    ui.messages.append(welcome);
    return;
  }
  const messages = state.conversations.get(peer.identityId) || [];
  if (!messages.length) {
    const welcome = document.createElement("div");
    welcome.className = "welcome";
    const strong = document.createElement("strong");
    strong.textContent = peer.verified ? "Secure session ready." : "Verification required.";
    welcome.append(strong, document.createTextNode(peer.verified
      ? "This device pinned both of this contact’s fingerprints."
      : "Compare both fingerprints outside this chat before trusting this identity."));
    ui.messages.append(welcome);
    return;
  }
  for (const item of messages) {
    const bubble = document.createElement("article");
    bubble.className = "message " + item.direction;
    const content = document.createElement("div");
    content.textContent = item.text;
    const meta = document.createElement("small");
    meta.className = "message-meta";
    meta.textContent = (item.direction === "outgoing" ? "You · encrypted" : peer.nickname + " · signature verified") + " · " + item.time;
    bubble.append(content, meta);
    ui.messages.append(bubble);
  }
  ui.messages.scrollTop = ui.messages.scrollHeight;
}

function updateConversation() {
  const peer = selectedPeer();
  if (!peer) {
    ui.conversationName.textContent = "Select a peer";
    ui.conversationId.textContent = "No encrypted conversation selected";
    ui.securityChip.textContent = "Awaiting selection";
    ui.securityChip.className = "secure-chip warning";
    ui.verifyBanner.classList.remove("visible");
    ui.input.disabled = true;
    ui.sendButton.disabled = true;
  } else {
    ui.conversationName.textContent = peer.nickname;
    ui.conversationId.textContent = peer.identityId.slice(0, 12) + "…";
    ui.securityChip.textContent = peer.verified ? "✓ Verified identity" : "⚠ Verify identity";
    ui.securityChip.className = "secure-chip " + (peer.verified ? "" : "warning");
    ui.verifyBanner.classList.toggle("visible", !peer.verified);
    ui.input.disabled = !peer.verified;
    ui.sendButton.disabled = !peer.verified;
    ui.input.placeholder = peer.verified ? "Write an encrypted message…" : "Verify this peer before messaging…";
  }
  renderMessages();
}

function renderPeers() {
  const query = ui.peerFilter.value.trim().toLowerCase();
  const peers = Array.from(state.peers.values()).filter(peer =>
    !query || peer.nickname.toLowerCase().includes(query) || peer.identityId.includes(query));
  ui.peerList.replaceChildren();
  if (!peers.length) {
    const empty = document.createElement("p");
    empty.className = "empty-peers";
    empty.textContent = query ? "No online identity matches that search." : "No other verified identities are online yet.";
    ui.peerList.append(empty);
    return;
  }
  peers.sort((a, b) => a.nickname.localeCompare(b.nickname) || a.identityId.localeCompare(b.identityId));
  for (const peer of peers) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "peer-card" + (peer.identityId === state.activePeerId ? " selected" : "");
    card.setAttribute("aria-label", "Open chat with " + peer.nickname);
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = peerInitial(peer.nickname);
    const detail = document.createElement("span");
    const name = document.createElement("span");
    name.className = "peer-name";
    name.textContent = peer.nickname;
    const identity = document.createElement("span");
    identity.className = "peer-id";
    identity.textContent = peer.identityId.slice(0, 12);
    detail.append(name, identity);
    const badge = document.createElement("span");
    badge.className = "badge " + (peer.verified ? "verified" : "unverified");
    badge.textContent = peer.verified ? "VERIFIED" : "VERIFY";
    card.append(avatar, detail, badge);
    card.addEventListener("click", () => selectPeer(peer.identityId));
    ui.peerList.append(card);
  }
}

function addPeer(peer) {
  if (!state.peers.has(peer.identityId) && state.peers.size >= MAX_PEERS) {
    throw new Error("Online peer directory limit reached.");
  }
  state.peers.set(peer.identityId, peer);
}

function selectPeer(identityId) {
  state.activePeerId = identityId;
  ui.chatApp.classList.add("show-conversation");
  renderPeers();
  updateConversation();
}

function parseIdentityId(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("The relay supplied an invalid identity ID.");
  return value;
}

async function validateRsaKey(key, label) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (!jwk || jwk.kty !== "RSA" || jwk.e !== "AQAB" || typeof jwk.n !== "string") {
    throw new Error("Peer " + label + " key is not RSA-2048+ with exponent 65537.");
  }
  const modulus = b64urlToBytes(jwk.n);
  let start = 0;
  while (start < modulus.length && modulus[start] === 0) start += 1;
  const significant = modulus.subarray(start);
  if (!significant.length) throw new Error("Peer " + label + " key modulus is empty.");
  const bits = (significant.length - 1) * 8 + (32 - Math.clz32(significant[0]));
  if (bits < 2048 || bits > 8192) throw new Error("Peer " + label + " key must be 2048-8192 bits.");
}

async function parsePeer(entry) {
  if (!entry || typeof entry !== "object") throw new Error("Malformed peer record.");
  const identityId = parseIdentityId(entry.identity_id);
  const nickname = typeof entry.nickname === "string" ? entry.nickname.trim() : "";
  if (!nicknamePattern.test(nickname)) throw new Error("Peer has an invalid display name.");
  const signingDer = b64ToBytes(entry.signing_key);
  const encryptionDer = b64ToBytes(entry.encryption_key);
  if (hex(signingDer) === hex(encryptionDer)) throw new Error("Peer signing and encryption keys must differ.");
  const calculatedId = hex(await sha256(signingDer));
  if (calculatedId !== identityId) throw new Error("Peer identity does not match its signing key.");
  const signingKey = await crypto.subtle.importKey("spki", signingDer, { name: "RSA-PSS", hash: "SHA-256" }, true, ["verify"]);
  const encryptionKey = await crypto.subtle.importKey("spki", encryptionDer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  await validateRsaKey(signingKey, "signing");
  await validateRsaKey(encryptionKey, "encryption");
  const peer = {
    identityId, nickname, signingKey, encryptionKey,
    signingFingerprint: await fingerprint(signingDer), encryptionFingerprint: await fingerprint(encryptionDer),
    verified: false,
  };
  const known = readKnownPeers();
  const old = known[identityId];
  if (old) {
    if (old.signingFingerprint !== peer.signingFingerprint || old.encryptionFingerprint !== peer.encryptionFingerprint) {
      throw new Error("Key change rejected for " + nickname + " [" + identityId.slice(0, 12) + "].");
    }
    peer.verified = old.verified === true;
  } else {
    if (Object.keys(known).length >= MAX_KNOWN_PEERS) throw new Error("Peer pin limit reached.");
    known[identityId] = {
      nickname, signingFingerprint: peer.signingFingerprint,
      encryptionFingerprint: peer.encryptionFingerprint, verified: false,
    };
    if (!writeKnownPeers(known)) throw new Error("Could not persist peer pins; browser storage may be full.");
  }
  return peer;
}

async function ingestPeers(entries) {
  if (!Array.isArray(entries)) throw new Error("Malformed peer directory.");
  for (const entry of entries) {
    addPeer(await parsePeer(entry));
  }
  renderPeers();
  updateConversation();
}

function removePeer(identityId) {
  state.peers.delete(identityId);
  if (state.activePeerId === identityId) state.activePeerId = null;
  renderPeers();
  updateConversation();
}

async function authenticate(challengeB64) {
  const challenge = b64ToBytes(challengeB64, 32);
  const signingDer = state.identity.signingDer;
  const encryptionDer = state.identity.encryptionDer;
  const data = identifyData(challenge, state.identity.identityId, state.nickname, state.identity.signingHash, state.identity.encryptionHash);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, state.identity.signingPrivate, data));
  sendPacket({
    type: "IDENTIFY", v: V, nickname: state.nickname, identity_id: state.identity.identityId,
    signing_key: bytesToB64(signingDer), encryption_key: bytesToB64(encryptionDer), signature: bytesToB64(signature),
  });
}

function sendPacket(packet) {
  if (!state.socket || state.socket.readyState !== WebSocket.OPEN) throw new Error("Not connected to the relay.");
  state.socket.send(JSON.stringify(packet));
}

async function encryptMessage(plaintext, recipient) {
  const messageId = randomBytes(16);
  const nonce = randomBytes(12);
  const sessionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const rawSessionKey = new Uint8Array(await crypto.subtle.exportKey("raw", sessionKey));
  const wrappedKey = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP", label: OAEP_LABEL }, recipient.encryptionKey, rawSessionKey));
  const aad = messageAad(messageId, state.identity.identityId, recipient.identityId);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, sessionKey, encoder.encode(plaintext)));
  const wrappedKeyHash = await sha256(wrappedKey);
  const ciphertextHash = await sha256(ciphertext);
  const signed = signatureData(messageId, state.identity.identityId, recipient.identityId, wrappedKeyHash, nonce, ciphertextHash);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, state.identity.signingPrivate, signed));
  return {
    type: "MESSAGE", v: V, message_id: bytesToB64(messageId),
    sender_id: state.identity.identityId, recipient_id: recipient.identityId,
    encrypted_key: bytesToB64(wrappedKey), nonce: bytesToB64(nonce),
    ciphertext: bytesToB64(ciphertext), signature: bytesToB64(signature),
  };
}

async function decryptMessage(packet) {
  if (!packet || packet.type !== "MESSAGE" || packet.v !== V) throw new Error("Not a protocol-v2 message.");
  const messageId = b64ToBytes(packet.message_id, 16);
  const messageIdHex = hex(messageId);
  const senderId = parseIdentityId(packet.sender_id);
  const recipientId = parseIdentityId(packet.recipient_id);
  if (recipientId !== state.identity.identityId) throw new Error("Message was addressed to another identity.");
  if (state.seen.has(messageIdHex)) throw new Error("Replay rejected.");
  const peer = state.peers.get(senderId);
  if (!peer) throw new Error("Sender is not in the online directory.");
  if (!peer.verified) throw new Error("Sender is unverified; message was not decrypted.");
  const wrappedKey = b64ToBytes(packet.encrypted_key);
  const nonce = b64ToBytes(packet.nonce, 12);
  const ciphertext = b64ToBytes(packet.ciphertext);
  const signature = b64ToBytes(packet.signature);
  if (wrappedKey.length < 256 || wrappedKey.length > 1024 || signature.length < 256 || signature.length > 1024 ||
      ciphertext.length < 16 || ciphertext.length > MAX_PLAINTEXT_BYTES + 16) {
    throw new Error("Message fields have invalid lengths.");
  }
  const wrappedKeyHash = await sha256(wrappedKey);
  const ciphertextHash = await sha256(ciphertext);
  const signed = signatureData(messageId, senderId, recipientId, wrappedKeyHash, nonce, ciphertextHash);
  const signatureOk = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, peer.signingKey, signature, signed);
  if (!signatureOk) throw new Error("Message signature is invalid.");
  try {
    const rawKey = await crypto.subtle.decrypt({ name: "RSA-OAEP", label: OAEP_LABEL }, state.identity.encryptionPrivate, wrappedKey);
    if (rawKey.byteLength !== 32) throw new Error("Invalid session key.");
    const sessionKey = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: messageAad(messageId, senderId, recipientId) },
      sessionKey, ciphertext,
    );
    markMessageSeen(messageIdHex);
    return { peer, plaintext: decoder.decode(plaintext) };
  } catch {
    throw new Error("Encryption integrity check failed.");
  }
}

function allowIncoming() {
  const now = performance.now();
  state.incomingTokens = Math.min(60, state.incomingTokens + ((now - state.incomingUpdated) / 1000) * 20);
  state.incomingUpdated = now;
  if (state.incomingTokens < 1) return false;
  state.incomingTokens -= 1;
  return true;
}

async function handlePacket(raw) {
  if (typeof raw !== "string" || raw.length > MAX_FRAME_BYTES || encoder.encode(raw).length > MAX_FRAME_BYTES) {
    throw new Error("Invalid relay frame.");
  }
  const packet = JSON.parse(raw);
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) throw new Error("Invalid relay packet.");
  if (packet.type === "HELLO") {
    if (packet.v !== V) throw new Error("Relay does not support protocol v2.");
    await authenticate(packet.challenge);
  } else if (packet.type === "AUTH_OK") {
    if (packet.v !== V || packet.identity_id !== state.identity.identityId) throw new Error("Invalid relay authentication response.");
    state.authenticated = true;
    state.reconnectAttempts = 0;
    await ingestPeers(packet.peers);
    showChat();
    setPresence(true, "Securely connected");
    toast("Connected. Verify new peers before messaging.");
  } else if (packet.type === "USER_JOINED") {
    addPeer(await parsePeer(packet.peer));
    renderPeers();
    toast(packet.peer && typeof packet.peer.nickname === "string" ? packet.peer.nickname + " joined the relay." : "A peer joined the relay.");
  } else if (packet.type === "USER_LEFT") {
    const id = parseIdentityId(packet.identity_id);
    const peer = state.peers.get(id);
    removePeer(id);
    toast((peer ? peer.nickname : "A peer") + " left the relay.");
  } else if (packet.type === "USER_LIST") {
    await ingestPeers(packet.peers);
  } else if (packet.type === "MESSAGE") {
    const decoded = await decryptMessage(packet);
    addConversationMessage(decoded.peer.identityId, "incoming", decoded.plaintext);
    if (state.activePeerId !== decoded.peer.identityId) toast("Secure message received from " + decoded.peer.nickname + ".");
  } else if (packet.type === "ERROR") {
    toast("Relay: " + String(packet.msg || "Request failed.").slice(0, 500));
  } else {
    throw new Error("Unexpected relay packet.");
  }
}

function openSocket(url, automatic) {
  clearTimeout(state.reconnectTimer);
  state.url = url;
  state.authenticated = false;
  state.manuallyClosed = false;
  state.floodNotified = false;
  state.incomingTokens = 60;
  state.incomingUpdated = performance.now();
  setConnectionNote(automatic ? "Reconnecting securely…" : "Opening encrypted channel…", false);
  setPresence(false, "Connecting");
  try {
    state.socket = new WebSocket(url);
  } catch (error) {
    connectionFailed(error.message || "Could not open WebSocket.");
    return;
  }
  state.socket.onmessage = event => {
    if (state.queueDepth >= MAX_PACKET_QUEUE || !allowIncoming()) {
      if (!state.floodNotified) {
        state.floodNotified = true;
        toast("Relay data is arriving too quickly; extra packets were dropped.");
      }
      return;
    }
    state.queueDepth += 1;
    state.packetQueue = state.packetQueue
      .then(() => handlePacket(event.data))
      .catch(error => {
        toast("Rejected relay data: " + (error.message || "invalid packet."));
      })
      .finally(() => {
        state.queueDepth -= 1;
      });
  };
  state.socket.onerror = () => setConnectionNote("Network error. Check the relay URL and allowed origin.", true);
  state.socket.onclose = () => {
    state.socket = null;
    setPresence(false, "Disconnected");
    if (!state.manuallyClosed) {
      toast("Connection closed. Reconnecting…");
      scheduleReconnect();
    }
  };
}

function scheduleReconnect() {
  if (state.reconnectAttempts >= 5 || !state.url) {
    setConnectionNote("Connection closed. Use Connect to try again.", true);
    return;
  }
  const delay = Math.min(30000, 1000 * (2 ** state.reconnectAttempts));
  state.reconnectAttempts += 1;
  state.reconnectTimer = setTimeout(() => openSocket(state.url, true), delay);
}

function connectionFailed(message) {
  setConnectionNote(message, true);
  setPresence(false, "Disconnected");
  ui.connectButton.disabled = false;
  ui.connectButton.textContent = "Create identity & connect";
}

function showChat() {
  ui.onboarding.hidden = true;
  ui.chatApp.hidden = false;
  ui.selfName.textContent = state.nickname;
  ui.selfId.textContent = state.identity.identityId.slice(0, 20) + "…";
  renderPeers();
  updateConversation();
}

async function connect(event) {
  event.preventDefault();
  try {
    const nickname = ui.nickname.value.trim();
    if (!nicknamePattern.test(nickname)) throw new Error("Use 1–32 ASCII letters, digits, spaces, ., _, or - for the display name.");
    const url = normalizeUrl(ui.relayUrl.value.trim());
    ui.connectButton.disabled = true;
    ui.connectButton.textContent = "Preparing secure identity…";
    setConnectionNote("Private keys stay in this browser profile.", false);
    state.identity = await loadIdentity();
    const savedProfile = await dbGet("profile");
    if (savedProfile && savedProfile.nickname !== nickname) {
      throw new Error("This browser identity is already bound to the display name “" + savedProfile.nickname + "”.");
    }
    state.nickname = nickname;
    if (!savedProfile) await dbPut("profile", { nickname });
    loadSeenMessages();
    ui.connectButton.textContent = "Connecting…";
    openSocket(url, false);
  } catch (error) {
    connectionFailed(error.message || "Could not prepare secure identity.");
  }
}

function openVerification() {
  const peer = selectedPeer();
  if (!peer) return;
  ui.fingerprints.textContent = "Identity: " + peer.identityId + "\n\nSigning key:    " + peer.signingFingerprint + "\nEncryption key: " + peer.encryptionFingerprint;
  ui.verifyConfirmation.checked = false;
  ui.confirmVerify.disabled = true;
  ui.verifyDialog.showModal();
}

function trustSelectedPeer() {
  const peer = selectedPeer();
  if (!peer || !ui.verifyConfirmation.checked) return;
  const known = readKnownPeers();
  if (!known[peer.identityId]) return;
  known[peer.identityId].verified = true;
  if (!writeKnownPeers(known)) {
    toast("Could not save the verification; browser storage may be full.");
    return;
  }
  peer.verified = true;
  ui.verifyDialog.close();
  renderPeers();
  updateConversation();
  toast(peer.nickname + " is now pinned as verified on this device.");
}

async function sendMessage(event) {
  event.preventDefault();
  const peer = selectedPeer();
  const plaintext = ui.input.value.trim();
  if (!peer || !peer.verified || !plaintext) return;
  if (encoder.encode(plaintext).length > MAX_PLAINTEXT_BYTES) {
    toast("Message exceeds the 32 KB encrypted-message limit.");
    return;
  }
  try {
    ui.sendButton.disabled = true;
    sendPacket(await encryptMessage(plaintext, peer));
    addConversationMessage(peer.identityId, "outgoing", plaintext);
    ui.input.value = "";
  } catch (error) {
    toast("Message was not sent: " + (error.message || "encryption failed."));
  } finally {
    ui.sendButton.disabled = false;
  }
}

function bindEvents() {
  ui.connectForm.addEventListener("submit", connect);
  ui.peerFilter.addEventListener("input", renderPeers);
  ui.refreshPeers.addEventListener("click", () => {
    try { sendPacket({ type: "LIST_USERS", v: V }); } catch (error) { toast(error.message); }
  });
  ui.disconnect.addEventListener("click", () => {
    state.manuallyClosed = true;
    clearTimeout(state.reconnectTimer);
    if (state.socket) state.socket.close();
    state.socket = null;
    state.authenticated = false;
    state.peers.clear();
    state.conversations.clear();
    state.activePeerId = null;
    ui.chatApp.hidden = true;
    ui.onboarding.hidden = false;
    ui.connectButton.disabled = false;
    ui.connectButton.textContent = "Connect";
    setConnectionNote("Disconnected. Your local identity remains protected in this browser.", false);
  });
  ui.backToPeers.addEventListener("click", () => ui.chatApp.classList.remove("show-conversation"));
  ui.verifyPeer.addEventListener("click", openVerification);
  ui.cancelVerify.addEventListener("click", () => ui.verifyDialog.close());
  ui.verifyConfirmation.addEventListener("change", () => {
    ui.confirmVerify.disabled = !ui.verifyConfirmation.checked;
  });
  ui.confirmVerify.addEventListener("click", trustSelectedPeer);
  ui.composer.addEventListener("submit", sendMessage);
}

async function initialise() {
  bindEvents();
  const defaultUrl = location.host
    ? ((location.protocol === "https:" ? "wss://" : "ws://") + location.host)
    : "";
  ui.relayUrl.value = defaultUrl;
  try {
    state.db = await openIdentityDb();
    const profile = await dbGet("profile");
    if (profile && typeof profile.nickname === "string" && nicknamePattern.test(profile.nickname)) {
      ui.nickname.value = profile.nickname;
      ui.nickname.readOnly = true;
      ui.nickname.title = "Display name is bound to this browser identity.";
    }
  } catch {
    setConnectionNote("This browser blocked local identity storage. Enable site storage, then reload.", true);
    ui.connectButton.disabled = true;
  }
}

initialise();
