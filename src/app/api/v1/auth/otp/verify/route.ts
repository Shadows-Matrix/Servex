import { handleRoute, ok, parseJsonBody } from "@/lib/api";
import { otpVerifySchema } from "@/lib/validation";
import { otpService } from "@/services/otp.service";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  return handleRoute(async () => {
    const body = await parseJsonBody(req);
    const input = otpVerifySchema.parse(body);
    return ok(await otpService.verify(input));
  });
}