import "dotenv/config";
import express, { Request, Response } from "express";
import session from "express-session";
import { engine } from "express-handlebars";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import { createHmac, randomBytes } from "node:crypto";
import {
  getUserByUsername,
  getUserById,
  createUser,
  enableUserTotp,
  disableUserTotp,
  User,
} from "./db";

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 16) {
  throw new Error("SESSION_SECRET must be set in .env and be at least 16 characters");
}

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 12;
const APP_NAME = "Rasotec Demo";
const PUSH_SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes

declare module "express-session" {
  interface SessionData {
    userId: number;
    username: string;
    pendingUserId: number;
    pendingUsername: string;
    setupTotpSecret: string;
    pushSessionId: string;
  }
}

// ── In-memory push session store ──────────────────────────────────────────────

interface PushSession {
  userId: number;
  username: string;
  expires: number; // unix timestamp (seconds)
  authenticated: boolean;
}

const pushSessions = new Map<string, PushSession>();

function computePushHmac(
  totpSecret: string,
  account: string,
  issuer: string,
  endpoint: string,
  expires: number,
  sessionId: string
): string {
  const message = [account, issuer, endpoint, String(expires), sessionId].join("\n");
  return createHmac("sha256", totpSecret).update(message).digest("hex");
}

// ── Express setup ─────────────────────────────────────────────────────────────

app.engine("hbs", engine({ extname: ".hbs", defaultLayout: "main" }));
app.set("view engine", "hbs");
app.set("views", "./views");

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 },
  })
);

// ── Home ──────────────────────────────────────────────────────────────────────

app.get("/", (req: Request, res: Response) => {
  res.redirect(req.session.userId ? "/dashboard" : "/login");
});

// ── Registration ──────────────────────────────────────────────────────────────

app.get("/register", (req: Request, res: Response) => {
  if (req.session.userId) return void res.redirect("/dashboard");
  res.render("register", { title: "Register", error: req.query.error });
});

app.post("/register", async (req: Request, res: Response) => {
  const { username, password } = req.body as { username?: string; password?: string };

  if (!username || !password) {
    return void res.redirect("/register?error=Username+and+password+are+required");
  }
  const trimmedUsername = username.trim();
  if (trimmedUsername.length < 3) {
    return void res.redirect("/register?error=Username+must+be+at+least+3+characters");
  }
  if (password.length < 6) {
    return void res.redirect("/register?error=Password+must+be+at+least+6+characters");
  }
  if (getUserByUsername.get(trimmedUsername)) {
    return void res.redirect("/register?error=Username+already+taken");
  }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const result = createUser.run(trimmedUsername, hash);

  req.session.userId = result.lastInsertRowid as number;
  req.session.username = trimmedUsername;
  res.redirect("/dashboard");
});

// ── Login ─────────────────────────────────────────────────────────────────────

app.get("/login", (req: Request, res: Response) => {
  if (req.session.userId) return void res.redirect("/dashboard");
  res.render("login", { title: "Sign in", error: req.query.error, success: req.query.success });
});

app.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body as { username?: string; password?: string };

  if (!username || !password) {
    return void res.redirect("/login?error=Username+and+password+are+required");
  }

  const user = getUserByUsername.get(username.trim()) as User | undefined;
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return void res.redirect("/login?error=Invalid+username+or+password");
  }

  if (user.totp_enabled) {
    req.session.pendingUserId = user.id;
    req.session.pendingUsername = user.username;
    return void res.redirect("/2fa/verify");
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect("/dashboard");
});

// ── 2FA — Verify (manual code + push QR) ─────────────────────────────────────

app.get("/2fa/verify", async (req: Request, res: Response) => {
  if (req.session.userId) return void res.redirect("/dashboard");
  if (!req.session.pendingUserId) return void res.redirect("/login");

  const user = getUserById.get(req.session.pendingUserId) as User | undefined;

  let pushQrCode: string | undefined;
  let pushSessionId: string | undefined;
  let otpauthUrlForDisplay: string | undefined;

  if (user?.totp_secret) {
    pushSessionId = randomBytes(16).toString("hex");
    const expires = Math.floor((Date.now() + PUSH_SESSION_TTL_MS) / 1000);
    const endpoint = `${req.protocol}://${req.get("host")}/2fa/push`;
    const hmac = computePushHmac(
      user.totp_secret,
      user.username,
      APP_NAME,
      endpoint,
      expires,
      pushSessionId
    );

    const params = new URLSearchParams({
      action: "login",
      issuer: APP_NAME,
      endpoint,
      expires: String(expires),
      session: pushSessionId,
      hmac,
    });
    const otpauthUrl = `otpauth://totp/${encodeURIComponent(APP_NAME)}:${encodeURIComponent(user.username)}?${params}`;
    pushQrCode = await QRCode.toDataURL(otpauthUrl);
    otpauthUrlForDisplay = otpauthUrl;

    pushSessions.set(pushSessionId, {
      userId: user.id,
      username: user.username,
      expires,
      authenticated: false,
    });

    req.session.pushSessionId = pushSessionId;
  }

  res.render("2fa-verify", {
    title: "Two-Factor Authentication",
    error: req.query.error,
    pushQrCode,
    pushSessionId,
    otpauthUrl: otpauthUrlForDisplay,
  });
});

app.post("/2fa/verify", (req: Request, res: Response) => {
  if (!req.session.pendingUserId) return void res.redirect("/login");

  const { token } = req.body as { token?: string };
  const user = getUserById.get(req.session.pendingUserId) as User | undefined;

  if (!user?.totp_secret || !token || !authenticator.verify({ token, secret: user.totp_secret })) {
    return void res.redirect("/2fa/verify?error=Invalid+authentication+code");
  }

  // Clean up any pending push session
  if (req.session.pushSessionId) {
    pushSessions.delete(req.session.pushSessionId);
    delete req.session.pushSessionId;
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  res.redirect("/dashboard");
});

// ── 2FA — Push (called by mobile app) ────────────────────────────────────────

app.post("/2fa/push", (req: Request, res: Response) => {
  const { version, session: sessionId, account, otp } = req.body as {
    version?: string;
    session?: string;
    account?: string;
    otp?: string;
  };

  if (!sessionId || !account || !otp) {
    return void res.status(400).json({ error: "Missing required fields" });
  }

  const pushSession = pushSessions.get(sessionId);
  if (!pushSession) {
    return void res.status(404).json({ error: "Session not found" });
  }
  if (Date.now() > pushSession.expires * 1000) {
    pushSessions.delete(sessionId);
    return void res.status(410).json({ error: "Session expired" });
  }

  const user = getUserById.get(pushSession.userId) as User | undefined;
  if (!user?.totp_secret || user.username !== account) {
    return void res.status(400).json({ error: "Invalid account" });
  }
  if (!authenticator.verify({ token: otp, secret: user.totp_secret })) {
    return void res.status(401).json({ error: "Invalid OTP" });
  }

  pushSession.authenticated = true;
  res.json({ success: true });
});

// ── 2FA — Push status (polled by browser) ────────────────────────────────────

app.get("/2fa/push/status", (req: Request, res: Response) => {
  const sessionId = req.query.session as string | undefined;
  if (!sessionId) return void res.json({ status: "invalid" });

  const pushSession = pushSessions.get(sessionId);
  if (!pushSession) return void res.json({ status: "invalid" });

  if (Date.now() > pushSession.expires * 1000) {
    pushSessions.delete(sessionId);
    return void res.json({ status: "expired" });
  }

  res.json({ status: pushSession.authenticated ? "authenticated" : "pending" });
});

// ── 2FA — Push complete (browser redirect after polling succeeds) ─────────────

app.get("/2fa/push/complete", (req: Request, res: Response) => {
  const sessionId = req.query.session as string | undefined;

  if (!sessionId || req.session.pushSessionId !== sessionId) {
    return void res.redirect("/login?error=Push+authentication+failed");
  }

  const pushSession = pushSessions.get(sessionId);
  if (!pushSession?.authenticated || Date.now() > pushSession.expires * 1000) {
    return void res.redirect("/login?error=Push+authentication+failed");
  }

  // Verify the push session belongs to the same pending user as this browser
  if (req.session.pendingUserId !== pushSession.userId) {
    return void res.redirect("/login?error=Session+mismatch");
  }

  pushSessions.delete(sessionId);

  req.session.userId = pushSession.userId;
  req.session.username = pushSession.username;
  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  delete req.session.pushSessionId;
  res.redirect("/dashboard");
});

// ── 2FA — Setup ───────────────────────────────────────────────────────────────

app.get("/2fa/setup", async (req: Request, res: Response) => {
  if (!req.session.userId) return void res.redirect("/login");

  const secret = authenticator.generateSecret();
  req.session.setupTotpSecret = secret;

  const otpauth = authenticator.keyuri(req.session.username, APP_NAME, secret);
  const qrCode = await QRCode.toDataURL(otpauth);

  res.render("2fa-setup", {
    title: "Enable Two-Factor Authentication",
    qrCode,
    secret,
    error: req.query.error,
  });
});

app.post("/2fa/setup", (req: Request, res: Response) => {
  if (!req.session.userId) return void res.redirect("/login");

  const { token } = req.body as { token?: string };
  const secret = req.session.setupTotpSecret;

  if (!secret || !token || !authenticator.verify({ token, secret })) {
    return void res.redirect("/2fa/setup?error=Invalid+code,+please+try+again");
  }

  enableUserTotp.run(secret, req.session.userId);
  delete req.session.setupTotpSecret;
  res.redirect("/dashboard?success=Two-factor+authentication+enabled");
});

// ── 2FA — Disable ─────────────────────────────────────────────────────────────

app.post("/2fa/disable", (req: Request, res: Response) => {
  if (!req.session.userId) return void res.redirect("/login");

  const { token } = req.body as { token?: string };
  const user = getUserById.get(req.session.userId) as User | undefined;

  if (!user?.totp_secret || !token || !authenticator.verify({ token, secret: user.totp_secret })) {
    return void res.redirect("/dashboard?error=Invalid+code,+2FA+was+not+disabled");
  }

  disableUserTotp.run(req.session.userId);
  res.redirect("/dashboard?success=Two-factor+authentication+disabled");
});

// ── Dashboard ─────────────────────────────────────────────────────────────────

app.get("/dashboard", (req: Request, res: Response) => {
  if (!req.session.userId) return void res.redirect("/login");
  const user = getUserById.get(req.session.userId) as User;
  res.render("dashboard", {
    title: "Dashboard",
    username: req.session.username,
    totpEnabled: !!user.totp_enabled,
    error: req.query.error,
    success: req.query.success,
  });
});

// ── Logout ────────────────────────────────────────────────────────────────────

app.post("/logout", (req: Request, res: Response) => {
  req.session.destroy(() => {
    res.redirect("/login?success=You+have+been+signed+out");
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
