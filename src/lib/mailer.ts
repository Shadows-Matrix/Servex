import nodemailer from "nodemailer";

function smtpEnv() {
  const host = process.env.SMTP_HOST?.trim() || "";
  const portRaw = (process.env.SMTP_PORT?.trim() || "587").replace(/^"+|"+$/g, "");
  const port = Number(portRaw);
  const user = process.env.SMTP_USER?.trim() || "";
  const pass = process.env.SMTP_PASS || "";
  const from = process.env.SMTP_FROM?.trim() || user || "SERVEX <no-reply@servex.local>";
  return { host, portRaw, port, user, pass, from };
}

/** Live check — reads env on every call (never a stale import-time snapshot). */
export function isMailConfigured(): boolean {
  const { host, user, pass } = smtpEnv();
  const configured = Boolean(host && user && pass);
  mailConfigured = configured;
  return configured;
}

/** @deprecated Prefer isMailConfigured(). Kept as a live binding for old importers. */
export let mailConfigured: boolean = Boolean(
  process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS
);

let transporter: nodemailer.Transporter | null = null;
let transporterKey = "";
const verifiedKeys = new Set<string>();

function getTransporter() {
  const { host, port, portRaw, user, pass } = smtpEnv();
  if (!host) {
    throw new Error("SMTP_HOST is missing.");
  }
  if (!port || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(
      `SMTP_PORT "${portRaw}" is invalid. Use 587 for Gmail (STARTTLS) or 465 for SSL.`
    );
  }
  const key = `${host}:${port}:${user}`;
  if (!transporter || transporterKey !== key) {
    transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      // Gmail on 587 requires STARTTLS — enforce upgrade instead of silently sending cleartext.
      requireTLS: port === 587,
      auth: { user, pass },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    });
    transporterKey = key;
  }
  return { transporter, key };
}

/** Map nodemailer / SMTP errors to actionable, non-secret messages. */
export function friendlyMailError(err: unknown): string {
  const anyErr = err as { code?: string; responseCode?: number; command?: string; message?: string };
  const code = String(anyErr?.code ?? "").toUpperCase();
  const msg = String(anyErr?.message ?? err);
  const responseCode = anyErr?.responseCode;

  if (code === "EAUTH" || responseCode === 535 || /invalid login|bad credentials|username and password/i.test(msg)) {
    return (
      "Gmail rejected the sender login. Use a Gmail App password " +
      "(Google Account → Security → 2-Step Verification → App passwords), " +
      "not your normal Gmail password. SMTP_USER must be the full Gmail address."
    );
  }
  if (code === "EDNS" || code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return `Could not resolve SMTP host. Check SMTP_HOST (Gmail: smtp.gmail.com). Details: ${msg}`;
  }
  if (code === "ETIMEDOUT" || code === "ECONNECTION" || code === "ESOCKET" || code === "ECONNREFUSED") {
    return `Could not reach the SMTP server (timeout/refused). For Gmail use host smtp.gmail.com port 587. Details: ${msg}`;
  }
  if (responseCode === 550 || responseCode === 553 || responseCode === 552) {
    return `The email was rejected (SMTP ${responseCode}). Check the recipient address and the Gmail sender's sending limits. Details: ${msg}`;
  }
  if (/SMTP_PORT/i.test(msg)) return msg;
  return `Could not send the verification email. Check SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS. Details: ${msg}`;
}

export async function sendMail(to: string, subject: string, html: string, text: string) {
  if (!isMailConfigured()) {
    throw new Error("SMTP is not configured (set SMTP_HOST/SMTP_USER/SMTP_PASS)");
  }
  const { transporter: t, key } = getTransporter();
  try {
    if (!verifiedKeys.has(key)) {
      await t.verify();
      verifiedKeys.add(key);
    }
    const { from } = smtpEnv();
    await t.sendMail({ from, to, subject, html, text });
  } catch (err) {
    // Never keep a broken connection/config cached — next attempt re-verifies.
    transporter = null;
    throw new Error(friendlyMailError(err), { cause: err });
  }
}

export function otpEmailHtml(code: string) {
  return `
  <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e5e5e5;border-radius:12px">
    <h2 style="margin:0 0 8px">Your SERVEX verification code</h2>
    <p style="color:#555">Enter this code to finish signing in. It expires in 10 minutes.</p>
    <div style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;background:#f4f4f4;border-radius:8px;padding:16px;margin:16px 0">${code}</div>
    <p style="color:#888;font-size:12px">If you didn't request this, you can safely ignore this email.</p>
  </div>`;
}
