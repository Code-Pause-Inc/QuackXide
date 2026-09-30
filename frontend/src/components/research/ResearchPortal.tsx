import { useMemo, useState } from "react";
import { brand } from "../../config/brand";
import { errorMessage } from "../../lib/format";
import {
  type AccessRequestView,
  type BudgetView,
  type CatalogView,
  type GrantView,
  type ListingView,
  ResearchClient,
  formatMoney,
  formatRate,
  shortId,
  tenantFromJwt,
} from "../../lib/research/client";
import IssuedGrantRow from "./IssuedGrantRow";
import PublishForm from "./PublishForm";
import { inputCls, primaryBtnCls, quietBtnCls } from "./styles";
import { Meter, SectionLabel, StatusChip } from "./ui";

// Research portal for both roles. Researchers see authorized datasets and the
// priced catalog and can request access; stewards review requests, manage
// listings, and top up or revoke issued access. The token is pasted in (or
// prefilled from VITE_DEV_JWT) for development.

const NOTE_MAX = 1000;

interface PortalData {
  catalog: CatalogView;
  grants: GrantView[];
  budgets: Record<string, BudgetView>;
  requests: AccessRequestView[];
}

function findListing(
  listings: ListingView[],
  steward: string,
  connector: string,
): ListingView | undefined {
  return listings.find((l) => l.steward_tenant === steward && l.connector === connector);
}

export default function ResearchPortal() {
  const [token, setToken] = useState(import.meta.env.VITE_DEV_JWT ?? "");
  const [data, setData] = useState<PortalData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [requestingId, setRequestingId] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [showPublishForm, setShowPublishForm] = useState(false);

  const me = useMemo(() => tenantFromJwt(token), [token]);
  const client = () => new ResearchClient(brand.apiBaseUrl, token);

  const refresh = async () => {
    const c = client();
    const [catalog, grants, requests] = await Promise.all([
      c.catalog(),
      c.grants(),
      c.myRequests(),
    ]);
    const active = grants.filter((g) => !g.revoked);
    const budgetList = await Promise.all(
      active.map(async (g) => {
        try {
          return await c.budget(g.grant_id);
        } catch {
          return null;
        }
      }),
    );
    const budgets: Record<string, BudgetView> = {};
    for (const b of budgetList) if (b) budgets[b.grant_id] = b;
    setData({ catalog, grants, budgets, requests });
  };

  const connect = async () => {
    setError(null);
    setLoading(true);
    try {
      await refresh();
    } catch (err) {
      setError(errorMessage(err, "failed to load the portal"));
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  /** Runs an action, then reloads everything from the API. */
  const act = async (key: string, run: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await run();
      await refresh();
      return true;
    } catch (err) {
      setError(errorMessage(err, "action failed"));
      return false;
    } finally {
      setBusy(null);
    }
  };

  const submitRequest = async (listingId: string) => {
    const ok = await act(`request:${listingId}`, () =>
      client().requestAccess(listingId, note.trim()),
    );
    if (ok) {
      setRequestingId(null);
      setNote("");
    }
  };

  const authorized = useMemo(() => {
    if (!data || !me) return [];
    return data.grants
      .filter((g) => g.researcher_tenant === me && !g.revoked)
      .map((grant) => ({
        grant,
        listing: findListing(data.catalog.listings, grant.steward_tenant, grant.connector),
        budget: data.budgets[grant.grant_id],
      }));
  }, [data, me]);

  /** My latest request per listing; the API returns requests oldest-first. */
  const requestByListing = useMemo(() => {
    const map = new Map<string, AccessRequestView>();
    if (!data || !me) return map;
    for (const request of data.requests) {
      if (request.researcher_tenant === me) map.set(request.listing_id, request);
    }
    return map;
  }, [data, me]);

  const incomingPending = useMemo(
    () =>
      !data || !me
        ? []
        : data.requests.filter((r) => r.steward_tenant === me && r.status === "pending"),
    [data, me],
  );

  const myListings = useMemo(
    () => (!data || !me ? [] : data.catalog.listings.filter((l) => l.steward_tenant === me)),
    [data, me],
  );

  const issuedGrants = useMemo(
    () =>
      !data || !me ? [] : data.grants.filter((g) => g.steward_tenant === me && !g.revoked),
    [data, me],
  );

  const listingTitleFor = (steward: string, connector: string): string =>
    (data && findListing(data.catalog.listings, steward, connector)?.title) ?? connector;

  const hasActiveAccess = (listing: ListingView) =>
    authorized.some(
      (a) =>
        a.grant.steward_tenant === listing.steward_tenant &&
        a.grant.connector === listing.connector,
    );

  return (
    <section className="space-y-4">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <label className="block text-xs font-medium uppercase tracking-widest text-slate-400">
          Research access token
        </label>
        <div className="mt-2 flex gap-2">
          <input
            type="password"
            value={token}
            onChange={(ev) => setToken(ev.target.value)}
            placeholder="Bearer JWT issued for your tenant"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="button"
            onClick={connect}
            disabled={!token || loading}
            className="rounded-lg bg-teal-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-teal-400 disabled:opacity-40"
          >
            {loading ? "Loading…" : "Open portal"}
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </p>
      )}

      {data && (
        <div className="rounded-2xl bg-white text-slate-900 shadow-sm ring-1 ring-slate-200">
          <header className="border-b border-slate-100 px-6 py-5">
            <h1 className="text-base font-semibold tracking-tight">Research data access</h1>
            <p className="mt-1 text-xs text-slate-500">
              Datasets remain sealed to their stewards. Queries return aggregate results only;
              small cohorts are suppressed before release.
            </p>
          </header>

          <div className="px-6 py-5">
            <SectionLabel>Authorized datasets</SectionLabel>
            {authorized.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">
                None yet. Request access from the catalog below; approved datasets appear here
                with their query allowance.
              </p>
            ) : (
              <ul className="mt-3 divide-y divide-slate-100">
                {authorized.map(({ grant, listing, budget }) => (
                  <li key={grant.grant_id} className="flex items-center gap-6 py-4">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">
                        {listing?.title ?? grant.connector}
                      </p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        steward {shortId(grant.steward_tenant)} · dataset {grant.connector}
                      </p>
                    </div>
                    <div className="w-48">
                      <p className="text-right text-xs tabular-nums text-slate-600">
                        {budget
                          ? `${budget.remaining} of ${budget.limit} queries left`
                          : "allowance unavailable"}
                      </p>
                      <div className="mt-1.5">
                        <Meter spent={budget?.spent ?? 0} limit={budget?.limit ?? 0} />
                      </div>
                    </div>
                    <StatusChip tone="active" label="Active" />
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="border-t border-slate-100 px-6 py-5">
            <SectionLabel>Dataset catalog</SectionLabel>
            {data.catalog.listings.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">No datasets are currently published.</p>
            ) : (
              <ul className="mt-3 divide-y divide-slate-100">
                {data.catalog.listings.map((listing) => {
                  const currency = data.catalog.currency;
                  const request = requestByListing.get(listing.listing_id);
                  const own = me !== null && listing.steward_tenant === me;
                  const active = hasActiveAccess(listing);
                  const open = requestingId === listing.listing_id;
                  return (
                    <li key={listing.listing_id} className="py-4">
                      <div className="flex items-start gap-6">
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium">{listing.title}</p>
                          {listing.description && (
                            <p className="mt-1 text-xs leading-relaxed text-slate-500">
                              {listing.description}
                            </p>
                          )}
                          <p className="mt-1.5 text-xs text-slate-400">
                            steward {shortId(listing.steward_tenant)} · includes{" "}
                            {listing.grant_budget} queries
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium tabular-nums">
                            {formatMoney(listing.license_fee_cents, currency)}
                            <span className="ml-1 text-xs font-normal text-slate-400">
                              license
                            </span>
                          </p>
                          <p className="mt-0.5 text-xs tabular-nums text-slate-500">
                            {formatRate(listing.compute_rate_cents, currency)}
                          </p>
                        </div>
                        <div className="w-36 text-right">
                          {own ? (
                            <StatusChip tone="own" label="Your dataset" />
                          ) : active ? (
                            <StatusChip tone="active" label="Access active" />
                          ) : request?.status === "pending" ? (
                            <StatusChip tone="pending" label="Pending" />
                          ) : (
                            <div className="space-y-1.5">
                              {request?.status === "denied" && (
                                <StatusChip tone="declined" label="Declined" />
                              )}
                              <button
                                type="button"
                                onClick={() => {
                                  setRequestingId(open ? null : listing.listing_id);
                                  setNote("");
                                }}
                                className="w-full rounded-lg border border-teal-600 px-3 py-1.5 text-xs font-semibold text-teal-700 hover:bg-teal-50"
                              >
                                {request?.status === "denied"
                                  ? "Request again"
                                  : "Request access"}
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                      {open && !own && !active && request?.status !== "pending" && (
                        <div className="mt-3 flex gap-2 rounded-lg bg-slate-50 p-3 ring-1 ring-slate-100">
                          <input
                            type="text"
                            value={note}
                            onChange={(ev) => setNote(ev.target.value)}
                            maxLength={NOTE_MAX}
                            placeholder="Purpose of access (e.g. IRB / protocol reference) — optional"
                            className={`${inputCls} flex-1`}
                          />
                          <button
                            type="button"
                            onClick={() => submitRequest(listing.listing_id)}
                            disabled={busy !== null}
                            className={primaryBtnCls}
                          >
                            {busy === `request:${listing.listing_id}`
                              ? "Sending…"
                              : "Submit request"}
                          </button>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <footer className="border-t border-slate-100 px-6 py-3 text-[11px] text-slate-500">
            Aggregate-only queries · small-cohort suppression · every query is metered against
            your allowance and audited. Billing is handled by {brand.publicName} on behalf of
            data stewards.
          </footer>
        </div>
      )}

      {data && (
        <div className="rounded-2xl bg-white text-slate-900 shadow-sm ring-1 ring-slate-200">
          <header className="border-b border-slate-100 px-6 py-5">
            <h1 className="text-base font-semibold tracking-tight">Data stewardship</h1>
            <p className="mt-1 text-xs text-slate-500">
              Publish datasets to the catalog, review access requests, and manage issued
              access. Your data never leaves its sealed form; approvals only permit metered
              aggregate queries.
            </p>
          </header>

          {incomingPending.length > 0 && (
            <div className="px-6 py-5">
              <SectionLabel>Access requests</SectionLabel>
              <ul className="mt-3 divide-y divide-slate-100">
                {incomingPending.map((request) => (
                  <li key={request.request_id} className="flex items-center gap-4 py-4">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">
                        {listingTitleFor(request.steward_tenant, request.connector)}
                      </p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        researcher {shortId(request.researcher_tenant)} ·{" "}
                        {request.created_at_iso.slice(0, 10)}
                      </p>
                      <p className="mt-1 text-xs italic text-slate-600">
                        {request.note ? `“${request.note}”` : "No purpose stated."}
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() =>
                        act(`approve:${request.request_id}`, () =>
                          client().approveRequest(request.request_id),
                        )
                      }
                      className={primaryBtnCls}
                    >
                      {busy === `approve:${request.request_id}` ? "Approving…" : "Approve"}
                    </button>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() =>
                        act(`deny:${request.request_id}`, () =>
                          client().denyRequest(request.request_id),
                        )
                      }
                      className={quietBtnCls}
                    >
                      Decline
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div
            className={`px-6 py-5 ${incomingPending.length > 0 ? "border-t border-slate-100" : ""}`}
          >
            <div className="flex items-center justify-between">
              <SectionLabel>Published listings</SectionLabel>
              <button
                type="button"
                onClick={() => setShowPublishForm(!showPublishForm)}
                className={quietBtnCls}
              >
                {showPublishForm ? "Close" : "Publish a dataset"}
              </button>
            </div>
            {showPublishForm && (
              <PublishForm
                busy={busy === "publish"}
                currency={data.catalog.currency}
                onPublish={(body) =>
                  act("publish", () => client().publishListing(body)).then(
                    (ok) => ok && setShowPublishForm(false),
                  )
                }
              />
            )}
            {myListings.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">
                Nothing published. Listings make a sealed dataset discoverable — with your
                license fee and compute rate — without exposing any of its contents.
              </p>
            ) : (
              <ul className="mt-3 divide-y divide-slate-100">
                {myListings.map((listing) => (
                  <li key={listing.listing_id} className="flex items-center gap-6 py-4">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{listing.title}</p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        dataset {listing.connector} · includes {listing.grant_budget} queries
                      </p>
                    </div>
                    <p className="text-xs tabular-nums text-slate-600">
                      {formatMoney(listing.license_fee_cents, data.catalog.currency)} license ·{" "}
                      {formatRate(listing.compute_rate_cents, data.catalog.currency)}
                    </p>
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() =>
                        act(`withdraw:${listing.listing_id}`, () =>
                          client().withdrawListing(listing.listing_id),
                        )
                      }
                      className={quietBtnCls}
                    >
                      {busy === `withdraw:${listing.listing_id}` ? "Withdrawing…" : "Withdraw"}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {issuedGrants.length > 0 && (
            <div className="border-t border-slate-100 px-6 py-5">
              <SectionLabel>Issued access</SectionLabel>
              <ul className="mt-3 divide-y divide-slate-100">
                {issuedGrants.map((grant) => (
                  <IssuedGrantRow
                    key={grant.grant_id}
                    grant={grant}
                    budget={data.budgets[grant.grant_id]}
                    title={listingTitleFor(grant.steward_tenant, grant.connector)}
                    busy={busy !== null}
                    onTopUp={(grantId, additional) =>
                      act(`topup:${grantId}`, () => client().topUpBudget(grantId, additional))
                    }
                    onRevoke={(grantId) =>
                      act(`revoke:${grantId}`, () => client().revokeGrant(grantId))
                    }
                  />
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
