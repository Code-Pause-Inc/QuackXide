// Research portal API client: catalog, access requests, grants, and budgets.

export interface ListingView {
  listing_id: string;
  steward_tenant: string;
  connector: string;
  title: string;
  description: string;
  license_fee_cents: number;
  compute_rate_cents: number;
  grant_budget: number;
  published: boolean;
  created_at_iso: string;
  updated_at_iso: string;
}

export interface CatalogView {
  listings: ListingView[];
  currency: string;
}

export interface GrantView {
  grant_id: string;
  steward_tenant: string;
  researcher_tenant: string;
  connector: string;
  revoked: boolean;
  created_at_iso: string;
  updated_at_iso: string;
}

export interface BudgetView {
  grant_id: string;
  limit: number;
  spent: number;
  remaining: number;
}

export type RequestStatus = "pending" | "approved" | "denied";

export interface AccessRequestView {
  request_id: string;
  listing_id: string;
  steward_tenant: string;
  researcher_tenant: string;
  connector: string;
  note: string;
  status: RequestStatus;
  created_at_iso: string;
  updated_at_iso: string;
}

/** "$1,200" for whole amounts, "$0.40" otherwise; "12.00 XXX" for currency
 *  codes the runtime does not know. */
export function formatMoney(cents: number, currency: string): string {
  const amount = cents / 100;
  const fraction = cents % 100 === 0 ? 0 : 2;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency,
      minimumFractionDigits: fraction,
      maximumFractionDigits: 2,
    }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${currency}`;
  }
}

/** "$0.40 / query". */
export function formatRate(cents: number, currency: string): string {
  return `${formatMoney(cents, currency)} / query`;
}

/** Stable short display form of a tenant/grant UUID (first block). */
export function shortId(id: string): string {
  return id.split("-")[0] ?? id;
}

/** Reads the unverified `tid` claim for display and filtering only; the
 *  server verifies every request. */
export function tenantFromJwt(token: string): string | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(b64)) as { tid?: string };
    return typeof claims.tid === "string" && claims.tid ? claims.tid : null;
  } catch {
    return null;
  }
}

/** Parses "1200", "$1,200", or "0.40" into integer cents; null unless the
 *  input is a non-negative amount with at most two decimals. */
export function dollarsToCents(raw: string): number | null {
  const cleaned = raw.trim().replace(/^\$/, "").replace(/,/g, "");
  if (!/^\d+(\.\d{1,2})?$/.test(cleaned)) return null;
  const [whole, frac = ""] = cleaned.split(".");
  return Number(whole) * 100 + Number(`${frac}00`.slice(0, 2));
}

export function requestAccessPath(listingId: string): string {
  return `/api/v1/catalog/${encodeURIComponent(listingId)}/request`;
}

export function budgetPath(grantId: string): string {
  return `/api/v1/grants/${encodeURIComponent(grantId)}/budget`;
}

export function requestResolvePath(requestId: string, action: "approve" | "deny"): string {
  return `/api/v1/research/requests/${encodeURIComponent(requestId)}/${action}`;
}

export interface PublishListingBody {
  connector: string;
  title: string;
  description: string;
  license_fee_cents: number;
  compute_rate_cents: number;
  grant_budget?: number;
}

export interface ResolvedRequestView {
  request: AccessRequestView;
  grant?: GrantView & { budget?: BudgetView };
}

export class ResearchClient {
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

  private async get<T>(path: string, what: string): Promise<T> {
    const response = await fetch(this.url(path), { headers: this.headers() });
    if (response.status === 401) throw new Error("not authenticated");
    if (response.status === 503) throw new Error("research access is not enabled on this deployment");
    if (!response.ok) throw new Error(`failed to load ${what} (${response.status})`);
    return (await response.json()) as T;
  }

  async catalog(): Promise<CatalogView> {
    return this.get<CatalogView>("/api/v1/catalog", "the dataset catalog");
  }

  async grants(): Promise<GrantView[]> {
    const body = await this.get<{ grants: GrantView[] }>("/api/v1/grants", "authorized datasets");
    return body.grants;
  }

  async budget(grantId: string): Promise<BudgetView> {
    return this.get<BudgetView>(budgetPath(grantId), "budget standing");
  }

  async myRequests(): Promise<AccessRequestView[]> {
    const body = await this.get<{ requests: AccessRequestView[] }>(
      "/api/v1/research/requests",
      "access requests",
    );
    return body.requests;
  }

  async requestAccess(listingId: string, note: string): Promise<AccessRequestView> {
    const response = await fetch(this.url(requestAccessPath(listingId)), {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify({ note }),
    });
    if (response.status === 404) throw new Error("this dataset is no longer available");
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    return (await response.json()) as AccessRequestView;
  }

  private async send<T>(method: string, path: string, what: string, body?: object): Promise<T> {
    const response = await fetch(this.url(path), {
      method,
      headers: this.headers(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (response.status === 401) throw new Error("not authenticated");
    if (response.status === 404) throw new Error(`${what}: not found`);
    if (!response.ok) throw new Error(`${what} failed (${response.status})`);
    return (await response.json()) as T;
  }

  // Steward operations

  async publishListing(body: PublishListingBody): Promise<ListingView> {
    return this.send<ListingView>("POST", "/api/v1/catalog", "publish", body);
  }

  async withdrawListing(listingId: string): Promise<ListingView> {
    return this.send<ListingView>(
      "DELETE",
      `/api/v1/catalog/${encodeURIComponent(listingId)}`,
      "withdraw",
    );
  }

  async approveRequest(requestId: string): Promise<ResolvedRequestView> {
    return this.send<ResolvedRequestView>(
      "POST",
      requestResolvePath(requestId, "approve"),
      "approve",
      {},
    );
  }

  async denyRequest(requestId: string): Promise<ResolvedRequestView> {
    return this.send<ResolvedRequestView>(
      "POST",
      requestResolvePath(requestId, "deny"),
      "decline",
      {},
    );
  }

  async topUpBudget(grantId: string, additional: number): Promise<BudgetView> {
    return this.send<BudgetView>("POST", budgetPath(grantId), "top-up", { additional });
  }

  async revokeGrant(grantId: string): Promise<GrantView> {
    return this.send<GrantView>(
      "DELETE",
      `/api/v1/grants/${encodeURIComponent(grantId)}`,
      "revoke",
    );
  }
}
