# demo-auth-server

A minimal TypeScript web app for exploring new authentication methods. It implements standard username/password login as a baseline, then layers on TOTP-based two-factor authentication including a [push extension](https://github.com/rasotec/otp_push) — where a QR code on the login page lets a mobile authenticator app approve the login without the user typing a code.

## Stack

- **Runtime:** Node.js v22 LTS
- **Framework:** Express
- **Database:** SQLite via Node's built-in `node:sqlite`
- **Password hashing:** bcryptjs
- **Sessions:** express-session
- **TOTP / 2FA:** otplib + qrcode

## Getting started

```bash
yarn install
yarn dev
```

Then open [http://localhost:3000](http://localhost:3000).

## Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirects to dashboard or login |
| GET | `/register` | Registration page |
| POST | `/register` | Submit registration |
| GET | `/login` | Login page |
| POST | `/login` | Submit login |
| GET | `/dashboard` | Protected page (requires login) |
| POST | `/logout` | Sign out |
| GET | `/2fa/verify` | Enter TOTP code or scan push QR after login |
| POST | `/2fa/verify` | Submit TOTP code |
| POST | `/2fa/push` | Receive push authentication from mobile app |
| GET | `/2fa/push/status` | Poll push session status (browser) |
| GET | `/2fa/push/complete` | Complete login after push authentication |
| GET | `/2fa/setup` | Set up TOTP (generates QR code) |
| POST | `/2fa/setup` | Confirm and enable TOTP |
| POST | `/2fa/disable` | Disable TOTP (requires current code) |

## Project structure

```
src/
  db.ts       # SQLite setup, prepared statements, and TOTP helpers
  server.ts   # Express app and routes
auth.db       # SQLite database file (created on first run, gitignored)
```

## Notes

- Passwords are hashed with bcrypt (12 salt rounds)
- Sessions expire after 1 hour
- The session secret in `server.ts` should be replaced with a strong random value in production
- TOTP 2FA uses [otplib](https://github.com/yeojz/otplib); QR codes are generated with [qrcode](https://github.com/soldair/node-qrcode)
- The push authentication flow embeds a signed `otpauth://` URL in a QR code; the mobile app POSTs the OTP to `/2fa/push`, and the browser polls `/2fa/push/status` until authenticated
- Push sessions are held in-memory and expire after 5 minutes
