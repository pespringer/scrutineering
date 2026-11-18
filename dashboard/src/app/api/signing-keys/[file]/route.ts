import { dashboardDownload } from "../../_lib/backend";

/** One public key as PEM: `/api/signing-keys/<hex fingerprint>.pem`. */
export async function GET(request: Request, context: { params: Promise<{ file: string }> }) {
  const { file } = await context.params;
  return dashboardDownload(`/api/dashboard/signing-keys/${encodeURIComponent(file)}`, request);
}
