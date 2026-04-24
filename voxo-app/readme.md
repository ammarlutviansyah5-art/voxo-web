# VOXO full-stack revision

This package converts the existing VOXO front-end shell into a database-backed app scaffold.

Included:
- `backend/schema.sql` — SQLite schema covering auth, contacts, conversations, messages, replies, call logs, statuses, media, settings, blocked/pinned/archived chats, sessions.
- `backend/server.js` — Express + Socket.IO backend with JWT auth, OTP flow, password reset, contacts, messages, status uploads, call logs, and settings persistence.
- `frontend/voxo-client.js` — browser bridge that overrides placeholder actions from the current HTML.
- `index-7.revised.html` — your current HTML with the bridge script injected.

## Run
1. `cd backend`
2. `npm install`
3. `node server.js`
4. Open `index-7.revised.html` in a static server, or serve the whole folder so `frontend/voxo-client.js` is reachable.

## Notes
- OTP and password-reset delivery are logged to the backend console by default. Hook `sendOtpEmail` and `sendResetEmail` to SMTP in production.
- WebRTC media calls are signaled through Socket.IO; the actual peer connection still needs the client-side call UI.
- The current HTML file is still mostly a chat shell; the bridge wires the existing action buttons to real APIs and state persistence.
