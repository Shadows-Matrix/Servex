"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { User, Briefcase } from "lucide-react";
import { apiFetch, ApiClientError } from "@/lib/api-client";
import { cn } from "@/lib/utils";

const emailSchema = z.object({
  email: z.string().email("Enter a valid email address"),
});

const detailsSchema = z
  .object({
    name: z.string().min(2, "Name must be at least 2 characters").max(80),
    role: z.enum(["CUSTOMER", "PROVIDER"]),
    phone: z.string().max(24).optional(),
    city: z.string().max(80).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.role === "PROVIDER" && !data.city?.trim()) {
      ctx.addIssue({ code: "custom", path: ["city"], message: "City is required for provider accounts" });
    }
  });

function formatSecs(s: number) {
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function LoginForm({
  callbackUrl,
  initialEmail,
}: {
  callbackUrl?: string;
  initialEmail?: string;
}) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState(initialEmail ?? "");

  // Admin password step (admins skip OTP).
  const [needPassword, setNeedPassword] = useState(false);
  const [password, setPassword] = useState("");

  // OTP step.
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [devCode, setDevCode] = useState<string | null>(null);
  const [secsLeft, setSecsLeft] = useState(0);

  // Signup details step (verified-new email).
  const [signupToken, setSignupToken] = useState<string | null>(null);
  const [rolePicked, setRolePicked] = useState(false);

  const emailForm = useForm<z.infer<typeof emailSchema>>({
    resolver: zodResolver(emailSchema),
    defaultValues: { email: initialEmail ?? "" },
  });

  const detailsForm = useForm<z.infer<typeof detailsSchema>>({
    resolver: zodResolver(detailsSchema),
    defaultValues: { name: "", role: "CUSTOMER", phone: "", city: "" },
  });
  const detailsRole = detailsForm.watch("role");

  // Countdown for the 60-second code window.
  useEffect(() => {
    if (!challengeId || secsLeft <= 0) return;
    const t = setTimeout(() => setSecsLeft((s) => s - 1), 1000);
    return () => clearTimeout(t);
  }, [challengeId, secsLeft]);

  function goDashboard() {
    router.push(callbackUrl || "/customer");
    router.refresh();
  }

  async function requestCode(targetEmail: string) {
    setError("");
    setBusy(true);
    try {
      const res = await apiFetch<{
        requiresOtp: boolean;
        challengeId?: string;
        expiresInSecs?: number;
        devCode?: string;
      }>("/api/v1/auth/otp/request", {
        method: "POST",
        body: JSON.stringify({ email: targetEmail }),
      });
      if (!res.requiresOtp) {
        setNeedPassword(true);
        setChallengeId(null);
        return;
      }
      setNeedPassword(false);
      setEmail(targetEmail);
      setChallengeId(res.challengeId ?? null);
      setDevCode(res.devCode ?? null);
      setCode("");
      setSecsLeft(res.expiresInSecs ?? 60);
      setSignupToken(null);
    } catch (err) {
      // MAIL_FAILED (502) means the email never sent and no challenge was
      // kept — the user can retry immediately instead of waiting out resend.
      if (err instanceof ApiClientError && err.code === "MAIL_FAILED") {
        setError(`${err.message} You can retry right away — no need to wait.`);
      } else if (err instanceof ApiClientError && err.code === "DB_ERROR") {
        setError("Our database is briefly unavailable. Please try again in a moment.");
      } else {
        setError(err instanceof Error ? err.message : "Could not send code");
      }
    } finally {
      setBusy(false);
    }
  }

  async function onEmailSubmit(values: z.infer<typeof emailSchema>) {
    await requestCode(values.email);
  }

  async function onPasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const result = await signIn("credentials", {
        redirect: false,
        email,
        password,
      });
      if (result?.error) {
        setError("Invalid email or password.");
        return;
      }
      toast.success("Signed in successfully.");
      goDashboard();
    } finally {
      setBusy(false);
    }
  }

  async function onOtpSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!challengeId || code.length !== 6) return;
    setError("");
    setBusy(true);
    try {
      const res = await apiFetch<
        | { kind: "login"; email: string; loginToken: string }
        | { kind: "signup"; email: string; signupToken: string }
      >("/api/v1/auth/otp/verify", {
        method: "POST",
        body: JSON.stringify({ challengeId, code }),
      });
      if (res.kind === "login") {
        const result = await signIn("credentials", {
          redirect: false,
          email: res.email,
          password: "",
          loginToken: res.loginToken,
        });
        if (result?.error) {
          setError("Sign-in failed. Please try again.");
          return;
        }
        toast.success("Signed in successfully.");
        goDashboard();
      } else {
        setEmail(res.email);
        setSignupToken(res.signupToken);
        setRolePicked(false);
        setChallengeId(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDetailsSubmit(values: z.infer<typeof detailsSchema>) {
    if (!signupToken) return;
    setError("");
    setBusy(true);
    try {
      const res = await apiFetch<{ email: string; loginToken: string }>(
        "/api/v1/auth/register/complete",
        {
          method: "POST",
          body: JSON.stringify({ signupToken, ...values }),
        }
      );
      const result = await signIn("credentials", {
        redirect: false,
        email: res.email,
        password: "",
        loginToken: res.loginToken,
      });
      if (result?.error) {
        setError("Account created, but sign-in failed. Please sign in.");
        return;
      }
      toast.success("Welcome to SERVEX!");
      goDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  // ---------- Step 3b: new-user details ----------
  if (signupToken) {
    return (
      <div className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <div className="text-center">
          <p className="font-medium">Email verified ✓</p>
          <p className="mt-1 text-sm text-muted-foreground">
            <span className="font-medium">{email}</span> is yours. Tell us who you are to finish signing up.
          </p>
        </div>
        <Form {...detailsForm}>
          <form onSubmit={detailsForm.handleSubmit(onDetailsSubmit)} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => detailsForm.setValue("role", "CUSTOMER")}
                className={cn(
                  "flex flex-col items-center gap-1 rounded-xl border p-4 text-sm font-medium transition-colors",
                  detailsRole === "CUSTOMER" ? "border-primary bg-primary/5 text-primary" : "border-border text-muted-foreground hover:border-muted-foreground/40"
                )}
              >
                <User className="size-5" />
                I&apos;m a customer
              </button>
              <button
                type="button"
                onClick={() => detailsForm.setValue("role", "PROVIDER")}
                className={cn(
                  "flex flex-col items-center gap-1 rounded-xl border p-4 text-sm font-medium transition-colors",
                  detailsRole === "PROVIDER" ? "border-primary bg-primary/5 text-primary" : "border-border text-muted-foreground hover:border-muted-foreground/40"
                )}
              >
                <Briefcase className="size-5" />
                I&apos;m a provider
              </button>
            </div>
            <FormField
              control={detailsForm.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Full name</FormLabel>
                  <FormControl>
                    <Input placeholder="Your name" autoComplete="name" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {detailsRole === "PROVIDER" && (
              <>
                <FormField
                  control={detailsForm.control}
                  name="city"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>City where you work</FormLabel>
                      <FormControl>
                        <Input placeholder="e.g. Mumbai" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={detailsForm.control}
                  name="phone"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Phone (optional)</FormLabel>
                      <FormControl>
                        <Input placeholder="+91 98765 43210" autoComplete="tel" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Creating account…" : "Create account & sign in"}
            </Button>
          </form>
        </Form>
      </div>
    );
  }

  // ---------- Step 2: OTP ----------
  if (challengeId) {
    return (
      <div className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <div className="text-center">
          <p className="font-medium">Check your inbox</p>
          <p className="mt-1 text-sm text-muted-foreground">
            We sent a 6-digit code to <span className="font-medium">{email}</span>.
          </p>
          {devCode && (
            <p className="mt-2 rounded-lg bg-muted px-3 py-2 text-sm">
              Demo code: <span className="font-mono font-bold tracking-widest">{devCode}</span>
            </p>
          )}
        </div>
        <form onSubmit={onOtpSubmit} className="flex flex-col items-center gap-4">
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="••••••"
            maxLength={6}
            className="h-12 text-center font-mono text-2xl tracking-[0.5em]"
          />
          {secsLeft > 0 ? (
            <p className="text-sm text-muted-foreground">
              Resend available in <span className="font-mono font-semibold">{formatSecs(secsLeft)}</span>
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">Didn&apos;t get the code? Request a new one below.</p>
          )}
          <Button type="submit" className="w-full" disabled={busy || code.length !== 6}>
            {busy ? "Verifying…" : "Verify code"}
          </Button>
        </form>
        <div className="flex items-center justify-between text-sm">
          <button
            type="button"
            className="text-muted-foreground hover:text-foreground"
            onClick={() => {
              setChallengeId(null);
              setCode("");
              setError("");
            }}
          >
            ← Change email
          </button>
          <button
            type="button"
            className="font-medium text-primary hover:underline disabled:cursor-not-allowed disabled:opacity-40"
            onClick={() => requestCode(email)}
            disabled={busy || secsLeft > 0}
          >
            {secsLeft > 0 ? `Resend in ${formatSecs(secsLeft)}` : "Resend code"}
          </button>
        </div>
      </div>
    );
  }

  // ---------- Step 1b: admin password ----------
  if (needPassword) {
    return (
      <div className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <p className="text-center text-sm text-muted-foreground">
          Admin account <span className="font-medium">{email || "detected"}</span> — enter your password.
        </p>
        <form onSubmit={onPasswordSubmit} className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="admin-password">Password</label>
            <Input
              id="admin-password"
              type="password"
              placeholder="••••••••"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <Button type="submit" className="w-full" disabled={busy || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <button
          type="button"
          className="mx-auto block text-sm text-muted-foreground hover:text-foreground"
          onClick={() => {
            setNeedPassword(false);
            setPassword("");
            setError("");
          }}
        >
          ← Use a different email
        </button>
      </div>
    );
  }

  // ---------- Step 1: email ----------
  return (
    <div className="space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="text-center">
        <p className="font-medium">Sign in or sign up</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Enter your email — we&apos;ll send a 6-digit code to verify it&apos;s yours.
        </p>
      </div>
      <Form {...emailForm}>
        <form onSubmit={emailForm.handleSubmit(onEmailSubmit)} className="space-y-4">
          <FormField
            control={emailForm.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email</FormLabel>
                <FormControl>
                  <Input
                    type="email"
                    placeholder="you@example.com"
                    autoComplete="email"
                    {...field}
                    onChange={(e) => {
                      field.onChange(e);
                      setEmail(e.target.value);
                    }}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <Button type="submit" className="w-full" disabled={busy}>
            {busy ? "Sending code…" : "Send verification code"}
          </Button>
        </form>
      </Form>
    </div>
  );
}