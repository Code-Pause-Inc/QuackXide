import { useState } from "react";
import { brand } from "../../config/brand";
import { AdminClient, type TenantView } from "../../lib/admin/client";
import { errorMessage, formatBytes } from "../../lib/format";

// Tenant overview with storage usage and connector toggles. The admin JWT is
// pasted in (or prefilled from VITE_ADMIN_JWT) for development.
export default function AdminConsole() {
  const [token, setToken] = useState(import.meta.env.VITE_ADMIN_JWT ?? "");
  const [tenants, setTenants] = useState<TenantView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const client = () => new AdminClient(brand.apiBaseUrl, token);

  const load = async () => {
    setError(null);
    setLoading(true);
    try {
      setTenants(await client().listTenants());
    } catch (err) {
      setError(errorMessage(err, "failed to load tenants"));
    } finally {
      setLoading(false);
    }
  };

  const toggle = async (tenantId: string, slug: string, enabled: boolean) => {
    setBusy(`${tenantId}:${slug}`);
    setError(null);
    try {
      const updated = await client().toggleConnector(tenantId, slug, enabled);
      setTenants((prev) => prev.map((t) => (t.tenant_id === tenantId ? updated : t)));
    } catch (err) {
      setError(errorMessage(err, "toggle failed"));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <label className="block text-xs font-medium uppercase tracking-widest text-slate-400">
          Admin access token
        </label>
        <div className="mt-2 flex gap-2">
          <input
            type="password"
            value={token}
            onChange={(ev) => setToken(ev.target.value)}
            placeholder="Bearer JWT with the admin claim"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="button"
            onClick={load}
            disabled={!token || loading}
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-40"
          >
            {loading ? "Loading…" : "Load tenants"}
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </p>
      )}

      {tenants.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-500">
          No tenants loaded. Provide an admin token and load, or provision one via a{" "}
          {brand.publicName} subscription webhook.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-2xl border border-slate-800">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3">Tenant</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Plan</th>
                <th className="px-4 py-3">Storage</th>
                <th className="px-4 py-3">Connectors</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {tenants.map((tenant) => (
                <tr key={tenant.tenant_id} className="align-top">
                  <td className="px-4 py-3">
                    <div className="font-mono text-xs text-slate-300">{tenant.tenant_id}</div>
                    <div className="text-xs text-slate-500">sub {tenant.subscription_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs ${
                        tenant.status === "active"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : "bg-amber-500/15 text-amber-300"
                      }`}
                    >
                      {tenant.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300">{tenant.plan}</td>
                  <td className="px-4 py-3 text-slate-300">
                    {formatBytes(tenant.storage_bytes)}
                    <div className="text-xs text-slate-500">
                      {tenant.storage_object_count} objects
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(tenant.connectors).map(([slug, enabled]) => {
                        const key = `${tenant.tenant_id}:${slug}`;
                        return (
                          <button
                            key={slug}
                            type="button"
                            disabled={busy === key}
                            onClick={() => toggle(tenant.tenant_id, slug, !enabled)}
                            className={`rounded-lg border px-2.5 py-1 text-xs disabled:opacity-40 ${
                              enabled
                                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                                : "border-slate-700 text-slate-400 hover:border-slate-500"
                            }`}
                          >
                            {slug} · {enabled ? "on" : "off"}
                          </button>
                        );
                      })}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
