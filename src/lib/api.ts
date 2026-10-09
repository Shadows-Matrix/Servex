import { NextResponse } from "next/server";
import { ZodError } from "zod";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code: string = "ERROR"
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function ok<T>(data: T, status = 200) {
  return NextResponse.json({ data }, { status });
}

export function fail(status: number, message: string, code = "ERROR") {
  return NextResponse.json({ error: { code, message } }, { status });
}

/** Parse a JSON body, throwing a 400 ApiError (not a 500 SyntaxError) on failure. */
export async function parseJsonBody(req: Request): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    throw new ApiError(400, "Invalid request body. Expected JSON.", "BAD_REQUEST");
  }
}

/** Wraps a route handler with consistent error handling. */
export function handleRoute(handler: () => Promise<NextResponse>) {
  return handler().catch((err) => {
    if (err instanceof ApiError) {
      return fail(err.status, err.message, err.code);
    }
    if (err instanceof ZodError) {
      const message = err.issues
        .map((i) => `${i.path.join(".") || "body"}: ${i.message}`)
        .join("; ");
      return fail(422, message, "VALIDATION_ERROR");
    }
    // Empty / non-JSON bodies throw SyntaxError from req.json() — that's a
    // client error (400), not a server crash (500).
    if (err instanceof SyntaxError) {
      return fail(400, "Invalid request body. Expected JSON.", "BAD_REQUEST");
    }
    // Prisma connection / schema errors: surface a safe retryable code.
    // Only connection + missing-table/column codes map here; other known
    // request errors (e.g. unique-constraint P2002) fall through to 500
    // so service-level ApiErrors keep their specific status codes.
    const prismaCode = (err as { code?: string })?.code;
    if (
      prismaCode === "P1000" ||
      prismaCode === "P1001" ||
      prismaCode === "P1002" ||
      prismaCode === "P2021" ||
      prismaCode === "P2022" ||
      (err as Error)?.name === "PrismaClientInitializationError"
    ) {
      console.error("[API] database", err);
      return fail(503, "Database unavailable. Please try again in a moment.", "DB_ERROR");
    }
    console.error("[API]", err);
    // Safe-code policy: production clients get a stable code/message;
    // development also gets the real message for faster debugging.
    if (process.env.NODE_ENV !== "production") {
      const detail = err instanceof Error ? err.message : String(err);
      return fail(500, `Internal server error (${detail})`);
    }
    return fail(500, "Internal server error");
  });
}
