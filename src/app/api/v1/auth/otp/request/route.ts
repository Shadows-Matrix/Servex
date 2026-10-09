import { handleRoute, ok, parseJsonBody } from "@/lib/api";
import { otpRequestSchema } from "@/lib/validation";
import { otpService } from "@/services/otp.service";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  return handleRoute(async () => {
    const body = await parseJsonBody(req);
    const input = otpRequestSchema.parse(body);
    return ok(await otpService.request(input));
  });
}