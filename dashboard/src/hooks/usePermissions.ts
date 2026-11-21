"use client";

import { useEffect, useState } from "react";
import { getJson } from "@/lib/http";

export type Permissions = {
  roles?: string[];
  /** Actions from the server's role matrix (src/api/roles.py) that this session may take. */
  actions?: string[];
  can_manage_scans?: boolean;
  can_cancel_scans?: boolean;
  can_remediate?: boolean;
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

/** Whether the session may take an action; false until permissions load. */
export function can(permissions: Permissions, action: string): boolean {
  return Array.isArray(permissions.actions) && permissions.actions.includes(action);
}
