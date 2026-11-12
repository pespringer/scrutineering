import { dashboardMutationResponse } from "../../../../_lib/backend";

export async function POST(request: Request, { params }: { params: Promise<{ deliveryId: string }> }) {
  const { deliveryId } = await params;
  return dashboardMutationResponse(`/api/dashboard/remediations/alert-deliveries/${deliveryId}/replay`, request);
}
