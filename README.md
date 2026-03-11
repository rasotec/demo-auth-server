# demo-auth-server

A minimal TypeScript web app demonstrating user registration and login with session-based authentication.

## Stack

- **Runtime:** Node.js v23+
- **Framework:** Express
- **Database:** SQLite via Node's built-in `node:sqlite`
- **Password hashing:** bcryptjs
- **Sessions:** express-session

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

## Project structure

```
src/
  db.ts       # SQLite setup and prepared statements
  server.ts   # Express app, routes, and HTML templates
auth.db       # SQLite database file (created on first run, gitignored)
```

## Notes

- Passwords are hashed with bcrypt (12 salt rounds)
- Sessions expire after 1 hour
- The session secret in `server.ts` should be replaced with a strong random value in production
