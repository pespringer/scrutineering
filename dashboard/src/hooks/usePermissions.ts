"use client";

import { useEffect, useState } from "react";
import { getJson } from "@/lib/http";

export type Permissions = {
  can_manage_scans?: boolean;
  can_cancel_scans?: boolean;
  [key: string]: unknown;
};

/** Role-derived capabilities for the current session; empty until loaded or if the request fails. */
export function usePermissions(): Permissions {
  const [permissions, setPermissions] = useState<Permissions>({});
  useEffect(() => {
    getJson<Permissions>("/api/permissions")
      .then(setPermissions)
      .catch(() => setPermissions({}));
  }, []);
  return permissions;
}
