// Client for the backend /admin/* routes (requires an admin JWT).

export interface TenantView {
  tenant_id: string;
  status: "active" | "suspended";
  subscription_id: string;
  customer_id: string;
  plan: string;
  connectors: Record<string, boolean>;
  created_at_iso: string;
  updated_at_iso: string;
  storage_object_count: number;
  storage_bytes: number;
}

export function connectorTogglePath(tenantId: string, slug: string): string {
  return `/admin/tenants/${encodeURIComponent(tenantId)}/connectors/${encodeURIComponent(slug)}`;
}

export class AdminClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, "")}${path}`;
  }

  private headers(json = false): HeadersInit {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (json) headers["Content-Type"] = "application/json";
    return headers;
  }

  async listTenants(): Promise<TenantView[]> {
    const response = await fetch(this.url("/admin/tenants"), { headers: this.headers() });
    if (response.status === 401) throw new Error("not authenticated");
    if (response.status === 403) throw new Error("this token is not an admin token");
    if (!response.ok) throw new Error(`failed to load tenants (${response.status})`);
    const body = (await response.json()) as { tenants: TenantView[] };
    return body.tenants;
  }

  async toggleConnector(tenantId: string, slug: string, enabled: boolean): Promise<TenantView> {
    const response = await fetch(this.url(connectorTogglePath(tenantId, slug)), {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify({ enabled }),
    });
    if (!response.ok) throw new Error(`toggle failed (${response.status})`);
    return (await response.json()) as TenantView;
  }
}
