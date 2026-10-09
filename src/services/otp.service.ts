import { createHash, randomBytes, randomInt, timingSafeEqual } from "crypto";
import bcrypt from "bcryptjs";
import { ApiError } from "@/lib/api";
import { prisma } from "@/lib/prisma";
import type { z } from "zod";
import type { otpRequestSchema, otpVerifySchema, signupCompleteSchema } from "@/lib/validation";

export type OtpRequestInput = z.infer<typeof otpRequestSchema>;
export type OtpVerifyInput = z.infer<typeof otpVerifySchema>;
export type SignupCompleteInput = z.infer<typeof signupCompleteSchema>;

/** One-time code lifetime: 10 minutes. The on-screen 60s timer governs resends. */
const OTP_TTL_SECS = 600;
/** Minimum gap between two codes sent to the same email. */
const RESEND_COOLDOWN_SECS = 60;
const OTP_MAX_ATTEMPTS = 5;
const GRANT_TTL_MINS = 5;
const SIGNUP_PROOF_TTL_MINS = 10;

function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function safeEqualHex(a: string, b: string) {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Delivery of the one-time code.
 * Sends a real email when SMTP is configured; otherwise falls back to the
 * server log + dev code so local development still works.
 */
async function sendOtpCode(destination: string, code: string) {
  const { isMailConfigured, sendMail, otpEmailHtml } = await import("@/lib/mailer");
  if (isMailConfigured()) {
    await sendMail(
      destination,
      "Your SERVEX verification code",
      otpEmailHtml(code),
      `Your SERVEX verification code is ${code}. It expires in 10 minutes.`
    );
    return true;
  }
  console.log(`[OTP] SMTP not configured — code for ${destination}: ${code}`);
  return false;
}

export const otpService = {
  /**
   * Step 1 — one screen for login AND signup: enter email, get a code.
   * Works for existing and new emails alike; never reveals which it is.
   * Admins skip OTP and sign in with their password instead.
   */
  async request(input: OtpRequestInput) {
    const email = input.email.toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });

    if (user?.role === "ADMIN") {
      return { requiresOtp: false as const };
    }

    // Resend cooldown — one code per minute per email.
    const recent = await prisma.otpChallenge.findFirst({
      where: {
        expiresAt: { gt: new Date() },
        ...(user ? { userId: user.id } : { email }),
      },
      orderBy: { createdAt: "desc" },
    });
    if (recent) {
      const ageSecs = (Date.now() - recent.createdAt.getTime()) / 1000;
      if (ageSecs < RESEND_COOLDOWN_SECS) {
        throw new ApiError(
          429,
          `Please wait ${Math.ceil(RESEND_COOLDOWN_SECS - ageSecs)} seconds before requesting a new code.`,
          "RESEND_COOLDOWN"
        );
      }
      await prisma.otpChallenge.deleteMany({
        where: user ? { userId: user.id } : { email },
      });
    }

    const code = String(randomInt(100000, 1000000));
    const challenge = await prisma.otpChallenge.create({
      data: {
        userId: user?.id ?? null,
        email: user ? null : email,
        codeHash: sha256(code),
        expiresAt: new Date(Date.now() + OTP_TTL_SECS * 1000),
      },
    });

    await sendOtpCode(email, code).catch(async (mailErr) => {
      // Roll back the challenge so the user can retry immediately
      // instead of hitting RESEND_COOLDOWN on an email that never sent.
      await prisma.otpChallenge.delete({ where: { id: challenge.id } }).catch(() => {});
      const message = mailErr instanceof Error ? mailErr.message : "Could not send the verification email.";
      throw new ApiError(502, message, "MAIL_FAILED");
    });

    return {
      requiresOtp: true as const,
      challengeId: challenge.id,
      expiresInSecs: OTP_TTL_SECS,
      // Demo convenience only — never returned in production.
      devCode: process.env.NODE_ENV === "production" ? undefined : code,
    };
  },

  /**
   * Step 2 — verify the 6-digit code.
   * Existing email → login grant (step 3a: session).
   * New email → signup proof (step 3b: details form, then account creation).
   */
  async verify(input: OtpVerifyInput) {
    const challenge = await prisma.otpChallenge.findUnique({
      where: { id: input.challengeId },
      include: { user: true },
    });
    if (!challenge) {
      throw new ApiError(404, "Verification session expired. Request a new code.", "CHALLENGE_NOT_FOUND");
    }
    if (challenge.expiresAt.getTime() < Date.now()) {
      await prisma.otpChallenge.delete({ where: { id: challenge.id } });
      throw new ApiError(410, "Code expired. Request a new one.", "CODE_EXPIRED");
    }
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
      await prisma.otpChallenge.delete({ where: { id: challenge.id } });
      throw new ApiError(429, "Too many wrong attempts. Request a new code.", "TOO_MANY_ATTEMPTS");
    }

    if (!safeEqualHex(sha256(input.code), challenge.codeHash)) {
      await prisma.otpChallenge.update({
        where: { id: challenge.id },
        data: { attempts: { increment: 1 } },
      });
      throw new ApiError(401, "Incorrect code. Try again.", "INVALID_CODE");
    }

    const email = (challenge.user?.email ?? challenge.email ?? "").toLowerCase();
    await prisma.otpChallenge.delete({ where: { id: challenge.id } });

    // Re-check at verify time: the email may have registered since step 1.
    const user = challenge.userId
      ? challenge.user!
      : await prisma.user.findUnique({ where: { email } });
    if (user) {
      if (user.role === "ADMIN") {
        throw new ApiError(403, "Admins sign in with password.", "ADMIN_PASSWORD_ONLY");
      }
      const token = randomBytes(32).toString("hex");
      await prisma.loginGrant.create({
        data: {
          userId: user.id,
          tokenHash: sha256(token),
          expiresAt: new Date(Date.now() + GRANT_TTL_MINS * 60_000),
        },
      });
      return { kind: "login" as const, email: user.email, loginToken: token };
    }

    const signupToken = randomBytes(32).toString("hex");
    await prisma.signupProof.upsert({
      where: { email },
      update: { tokenHash: sha256(signupToken), expiresAt: new Date(Date.now() + SIGNUP_PROOF_TTL_MINS * 60_000), usedAt: null },
      create: {
        email,
        tokenHash: sha256(signupToken),
        expiresAt: new Date(Date.now() + SIGNUP_PROOF_TTL_MINS * 60_000),
      },
    });
    return { kind: "signup" as const, email, signupToken };
  },

  /**
   * Step 3b — create the account from a verified-new email.
   * The user row is created ONLY here: nothing is registered before the
   * 6-digit code is verified.
   */
  async completeSignup(input: SignupCompleteInput) {
    const proof = await prisma.signupProof.findUnique({
      where: { tokenHash: sha256(input.signupToken) },
    });
    if (!proof || proof.usedAt || proof.expiresAt.getTime() < Date.now()) {
      throw new ApiError(401, "Verification expired. Start again with your email.", "PROOF_INVALID");
    }

    const email = proof.email.toLowerCase();
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ApiError(409, "This email already has an account. Sign in instead.", "EMAIL_TAKEN");
    }
    if (input.role === "PROVIDER" && !input.city?.trim()) {
      throw new ApiError(422, "City is required for provider accounts.", "VALIDATION_ERROR");
    }

    // Passwordless accounts still need the NOT NULL hash column filled.
    const passwordHash = await bcrypt.hash(randomBytes(32).toString("hex"), 10);

    const user = await prisma.user.create({
      data: {
        name: input.name,
        email,
        passwordHash,
        role: input.role,
        phone: input.phone,
        city: input.city,
        ...(input.role === "PROVIDER"
          ? { providerProfile: { create: { city: input.city!, basePrice: 0 } } }
          : {}),
      },
    });

    await prisma.signupProof.update({
      where: { id: proof.id },
      data: { usedAt: new Date() },
    });

    const token = randomBytes(32).toString("hex");
    await prisma.loginGrant.create({
      data: {
        userId: user.id,
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + GRANT_TTL_MINS * 60_000),
      },
    });
    return { email: user.email, loginToken: token };
  },

  /** Consumed by the Credentials provider — single use, short lived. */
  async consumeGrant(email: string, loginToken: string) {
    const grant = await prisma.loginGrant.findUnique({
      where: { tokenHash: sha256(loginToken) },
      include: { user: true },
    });
    if (
      !grant ||
      grant.usedAt ||
      grant.expiresAt.getTime() < Date.now() ||
      grant.user.email.toLowerCase() !== email.toLowerCase()
    ) {
      return null;
    }
    await prisma.loginGrant.update({
      where: { id: grant.id },
      data: { usedAt: new Date() },
    });
    return grant.user;
  },
};