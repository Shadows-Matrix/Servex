export class ApiClientError extends Error {
  constructor(
    message: string,
    public code: string = "ERROR",
    public status: number = 0
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export async function apiFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const res = await fetch(input, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const json = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const errBody = (json as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiClientError(
      errBody?.message ?? `Request failed with status ${res.status}`,
      errBody?.code ?? "ERROR",
      res.status
    );
  }
  return (json as { data: T }).data;
}
