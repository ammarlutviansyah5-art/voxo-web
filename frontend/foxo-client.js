/* VOXO client bridge
   - overrides placeholder actions in index-7.html
   - expects backend at same origin or http://localhost:4000
*/
(() => {
  const API_BASE = window.VOXO_API_BASE || 'http://localhost:4000';
  const STORAGE_KEY = 'voxo.accessToken';
  const REFRESH_KEY = 'voxo.refreshToken';
  const SESSION_KEY = 'voxo.sessionId';

  const state = {
    me: null,
    settings: null,
    contacts: [],
    conversations: [],
    currentConversationId: null,
    currentTarget: null,
    socket: null,
  };

  function getToken() { return localStorage.getItem(STORAGE_KEY); }
  function setTokens({ accessToken, refreshToken, sessionId }) {
    if (accessToken) localStorage.setItem(STORAGE_KEY, accessToken);
    if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
    if (sessionId) localStorage.setItem(SESSION_KEY, sessionId);
  }
  function clearTokens() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(SESSION_KEY);
  }

  async function api(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error?.message || data?.error || 'Request gagal');
    return data;
  }

  async function uploadFile(file, kind = 'document') {
    const form = new FormData();
    form.append('file', file);
    form.append('kind', kind);
    const res = await fetch(`${API_BASE}/api/attachments`, {
      method: 'POST',
      headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
      body: form,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || 'Upload gagal');
    return data.media;
  }

  function toast(msg) {
    const existing = document.querySelector('.voxo-toast');
    if (existing) existing.remove();
    const t = document.createElement('div');
    t.className = 'voxo-toast';
    t.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#1e1e1e;border:1px solid rgba(255,107,26,0.25);color:#f0ece6;padding:8px 18px;border-radius:10px;font-size:12.5px;z-index:999;box-shadow:0 6px 20px rgba(0,0,0,0.4);font-family:Poppins,sans-serif;white-space:nowrap;';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2500);
  }
  window.showToast = toast;

  // ---------- AUTH ----------
  async function signup({ name, email, password }) {
    return api('/api/auth/signup', { method: 'POST', body: JSON.stringify({ name, email, password }) });
  }
  async function verifyEmailOtp({ email, otp }) {
    const data = await api('/api/auth/verify-email-otp', { method: 'POST', body: JSON.stringify({ email, otp }) });
    setTokens(data);
    await boot();
    return data;
  }
  async function login({ email, password }) {
    const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    setTokens(data);
    await boot();
    return data;
  }
  async function forgotPassword(email) {
    return api('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });
  }
  async function resetPassword({ email, token, newPassword }) {
    return api('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ email, token, newPassword }) });
  }
  async function logout() {
    try {
      await api('/api/auth/logout', { method: 'POST', body: JSON.stringify({ sessionId: localStorage.getItem(SESSION_KEY) }) });
    } catch {}
    clearTokens();
    window.location.reload();
  }

  // ---------- BOOT / RENDER ----------
  function setText(selector, value) {
    const el = document.querySelector(selector);
    if (el) el.textContent = value ?? '';
  }
  function setValue(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value ?? '';
  }
  function renderProfile() {
    if (!state.me) return;
    setText('.settings-name', state.me.name);
    setText('.settings-phone', state.me.voxo_id);
    setText('.nav-avatar', (state.me.name || 'U').charAt(0).toUpperCase());
    setText('#homePage .topbar span[style*="flex:1"]', `Selamat datang, ${state.me.name} 👋`);
    const heroAvatar = document.querySelector('.settings-avatar');
    if (heroAvatar) heroAvatar.textContent = (state.me.name || 'U').charAt(0).toUpperCase();
    const profileAv = document.getElementById('profileAv');
    if (profileAv) profileAv.textContent = (state.me.name || 'U').charAt(0).toUpperCase();
    setText('#profileName', state.me.name);
    setText('#profileNum', state.me.voxo_id);
    setText('#chatName', state.currentTarget?.display_name || state.me.name);
    if (state.settings) {
      const notif = document.querySelector('#settingsPage input[data-setting="notifications_enabled"]');
      if (notif) notif.checked = !!state.settings.notifications_enabled;
      const rr = document.querySelector('#settingsPage input[data-setting="read_receipts_enabled"]');
      if (rr) rr.checked = !!state.settings.read_receipts_enabled;
    }
  }

  function renderContacts() {
    const list = document.getElementById('homeContactList');
    if (!list) return;
    list.innerHTML = '';
    const contacts = state.contacts || [];
    if (!contacts.length) {
      list.innerHTML = '<div class="empty-state"><div class="empty-title">Belum ada kontak</div><div class="empty-sub">Tambahkan kontak dengan email, nomor VOXO, atau pencarian user.</div></div>';
      return;
    }
    contacts.forEach((c) => {
      const row = document.createElement('div');
      row.className = 'chat-item';
      row.dataset.contactId = c.id;
      row.dataset.contactEmail = c.contact_email || '';
      row.dataset.contactVoxoId = c.contact_voxo_id || '';
      row.innerHTML = `
        <div class="avatar av2">${(c.display_name || 'U').charAt(0).toUpperCase()}</div>
        <div class="chat-info">
          <div class="chat-name">${escapeHtml(c.display_name)}</div>
          <div class="chat-preview">${escapeHtml(c.contact_voxo_id || c.contact_email || c.contact_phone || 'Kontak tersimpan')}</div>
        </div>
        <div class="chat-meta"><button class="icon-btn orange" type="button">Chat</button></div>
      `;
      row.addEventListener('click', async () => {
        await openContactChat(c);
      });
      list.appendChild(row);
    });
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"]+/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
  }

  async function openContactChat(contact) {
    state.currentTarget = contact;
    const convo = await api('/api/conversations/direct', {
      method: 'POST',
      body: JSON.stringify({ email: contact.contact_email || undefined, voxo_id: contact.contact_voxo_id || undefined }),
    });
    state.currentConversationId = convo.conversation.id;
    if (typeof window.openChat === 'function') {
      window.openChat(null, contact.display_name, 'av2', '');
    }
    await loadMessages();
    ensureSocket();
  }

  async function loadBootstrap() {
    const data = await api('/api/chat/bootstrap');
    state.me = data.me;
    state.settings = data.settings;
    state.contacts = data.contacts || [];
    state.conversations = data.conversations || [];
    renderProfile();
    renderContacts();
  }

  async function boot() {
    if (!getToken()) return;
    try {
      await loadBootstrap();
      ensureSocket();
    } catch (e) {
      console.warn(e);
      clearTokens();
    }
  }

  // ---------- CHAT / MESSAGES ----------
  async function loadMessages() {
    const area = document.getElementById('messagesArea');
    if (!area || !state.currentConversationId) return;
    const data = await api(`/api/conversations/${state.currentConversationId}/messages`);
    area.innerHTML = '';
    data.messages.forEach((m) => {
      const row = document.createElement('div');
      row.className = `msg-row ${m.sender_id === state.me?.id ? 'out' : 'in'}`;
      row.innerHTML = `<div class="bubble">${escapeHtml(m.body || '')}<div class="bubble-time">${new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</div></div>`;
      area.appendChild(row);
    });
    area.scrollTop = area.scrollHeight;
  }

  async function sendMessage() {
    const input = document.getElementById('msgInput');
    if (!input) return;
    const body = input.value.trim();
    if (!body) return;
    if (!state.currentConversationId) return toast('Pilih kontak dulu');
    await api('/api/messages', {
      method: 'POST',
      body: JSON.stringify({ conversation_id: state.currentConversationId, body, type: 'text' }),
    });
    input.value = '';
    if (typeof window.closeReply === 'function') window.closeReply();
    await loadMessages();
  }

  async function replyToMsg() {
    toast('Reply siap dipakai melalui API messages');
    if (typeof window.closeMsgContext === 'function') window.closeMsgContext();
  }

  async function copyMsg() {
    toast('Salin pesan masih memakai clipboard browser');
  }

  async function saveContact() {
    const name = document.getElementById('contactName')?.value?.trim();
    const email = document.getElementById('contactNum')?.value?.trim();
    if (!name || !email) return toast('Nama dan email / nomor VOXO wajib diisi');
    await api('/api/contacts', { method: 'POST', body: JSON.stringify({ name, email: email.includes('@') ? email : undefined, voxo_id: email.includes('@') ? undefined : email }) });
    if (document.getElementById('contactName')) document.getElementById('contactName').value = '';
    if (document.getElementById('contactNum')) document.getElementById('contactNum').value = '';
    if (typeof window.closeModal === 'function') window.closeModal('saveModal');
    state.contacts = (await api('/api/contacts')).contacts;
    renderContacts();
    toast('Kontak tersimpan');
  }

  async function saveName() {
    const name = document.getElementById('newNameInput')?.value?.trim();
    if (!name) return toast('Nama tidak boleh kosong');
    await api('/api/me', { method: 'PATCH', body: JSON.stringify({ name }) });
    state.me = (await api('/api/me')).user;
    renderProfile();
    if (typeof window.closeModal === 'function') window.closeModal('editNameModal');
    toast('Nama diperbarui');
  }

  async function handleUpload(e) {
    const file = e?.target?.files?.[0];
    if (!file) return;
    try {
      const media = await uploadFile(file, e.target?.dataset?.kind || 'status');
      if (document.getElementById('fileUpload')) document.getElementById('fileUpload').value = '';
      await api('/api/statuses', { method: 'POST', body: JSON.stringify({ media_id: media.id, caption: '', visibility: 'my_contacts', expires_hours: 24 }) });
      toast('Status diupload');
    } catch (err) {
      toast(err.message);
    }
  }

  async function triggerUpload() {
    document.getElementById('fileUpload')?.click();
  }

  async function selectPrivacy(el) {
    document.querySelectorAll('#privacyList .privacy-radio-item').forEach((i) => i.classList.remove('selected'));
    el.classList.add('selected');
    const map = el.dataset.privacy;
    await api('/api/settings', { method: 'PATCH', body: JSON.stringify({ privacy_status: map }) });
    toast('Privasi status tersimpan');
  }

  async function toggleRecording() {
    toast('Voice note perlu integrasi MediaRecorder di client, metadata siap disimpan via /api/attachments');
  }

  async function attachDoc() { document.getElementById('docUpload')?.click(); }
  async function attachImage() { document.getElementById('imageUpload')?.click(); }
  async function attachCamera() { toast('Buka kamera'); }
  async function attachOnce() { toast('Foto sekali lihat aktif'); }

  async function toggleSetting(name, checked) {
    const payload = {};
    payload[name] = checked;
    await api('/api/settings', { method: 'PATCH', body: JSON.stringify(payload) });
    toast('Setting tersimpan');
  }

  function ensureSocket() {
    if (!window.io || state.socket || !getToken()) return;
    state.socket = window.io(API_BASE, { transports: ['websocket'] });
    state.socket.on('connect', () => {
      if (state.currentConversationId) state.socket.emit('conversation:join', { conversationId: state.currentConversationId });
    });
    state.socket.on('message:new', () => loadMessages().catch(() => {}));
    state.socket.on('message:edited', () => loadMessages().catch(() => {}));
    state.socket.on('message:deleted', () => loadMessages().catch(() => {}));
  }

  // expose methods to override inline placeholders
  window.VOXO = { api, signup, verifyEmailOtp, login, forgotPassword, resetPassword, logout, boot, state };
  window.saveContact = saveContact;
  window.saveName = saveName;
  window.sendMessage = sendMessage;
  window.triggerUpload = triggerUpload;
  window.handleUpload = handleUpload;
  window.selectPrivacy = selectPrivacy;
  window.toggleRecording = toggleRecording;
  window.attachDoc = attachDoc;
  window.attachImage = attachImage;
  window.attachCamera = attachCamera;
  window.attachOnce = attachOnce;
  window.replyToMsg = replyToMsg;
  window.copyMsg = copyMsg;
  window.showPage = window.showPage || function() {};

  document.addEventListener('DOMContentLoaded', () => {
    boot();
    const docUp = document.getElementById('fileUpload');
    if (docUp) docUp.addEventListener('change', handleUpload);
    const msgInput = document.getElementById('msgInput');
    if (msgInput) {
      msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendMessage().catch((err) => toast(err.message));
        }
      });
    }
  });
})();
