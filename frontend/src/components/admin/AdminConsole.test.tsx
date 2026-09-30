import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TenantView } from "../../lib/admin/client";
import AdminConsole from "./AdminConsole";

const api = vi.hoisted(() => ({
  constructed: vi.fn(),
  listTenants: vi.fn(),
  toggleConnector: vi.fn(),
}));

vi.mock("../../lib/admin/client", () => ({
  AdminClient: class {
    constructor(baseUrl: string, token: string) {
      api.constructed(baseUrl, token);
    }
    listTenants = api.listTenants;
    toggleConnector = api.toggleConnector;
  },
}));

const tenant: TenantView = {
  tenant_id: "6f2c8a2e-1111-4222-8333-444455556666",
  status: "active",
  subscription_id: "sub-001",
  customer_id: "cus-001",
  plan: "research",
  connectors: { health: true, claims: false },
  created_at_iso: "2026-07-01T00:00:00.000Z",
  updated_at_iso: "2026-07-01T00:00:00.000Z",
  storage_object_count: 42,
  storage_bytes: 1.5 * 1024 * 1024,
};

async function loadWith(token = "admin.jwt") {
  const user = userEvent.setup();
  render(<AdminConsole />);
  const input = screen.getByPlaceholderText(/admin claim/i);
  await user.clear(input);
  await user.type(input, token);
  await user.click(screen.getByRole("button", { name: "Load tenants" }));
  return user;
}

describe("AdminConsole", () => {
  beforeEach(() => {
    api.listTenants.mockResolvedValue([tenant]);
  });

  it("requires a token before loading", () => {
    render(<AdminConsole />);
    expect(screen.getByRole("button", { name: "Load tenants" })).toBeDisabled();
    expect(screen.getByText(/no tenants loaded/i)).toBeInTheDocument();
  });

  it("shows a loading state, then the tenant table with storage usage", async () => {
    let finish!: (tenants: TenantView[]) => void;
    api.listTenants.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    await loadWith("admin.jwt");

    expect(screen.getByRole("button", { name: "Loading…" })).toBeDisabled();
    expect(api.constructed).toHaveBeenCalledWith(expect.any(String), "admin.jwt");

    finish([tenant]);
    const row = within(await screen.findByRole("row", { name: new RegExp(tenant.tenant_id) }));
    expect(row.getByText("active")).toBeInTheDocument();
    expect(row.getByText("research")).toBeInTheDocument();
    expect(row.getByText("1.5 MB")).toBeInTheDocument();
    expect(row.getByText("42 objects")).toBeInTheDocument();
    expect(row.getByRole("button", { name: "health · on" })).toBeInTheDocument();
    expect(row.getByRole("button", { name: "claims · off" })).toBeInTheDocument();
  });

  it("shows the client's error message when loading fails", async () => {
    api.listTenants.mockRejectedValue(new Error("this token is not an admin token"));
    await loadWith();
    expect(await screen.findByText("this token is not an admin token")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("falls back to a generic message for non-Error failures", async () => {
    api.listTenants.mockRejectedValue({ status: 500 });
    await loadWith();
    expect(await screen.findByText("failed to load tenants")).toBeInTheDocument();
  });

  it("toggles a connector and renders the updated tenant", async () => {
    api.toggleConnector.mockResolvedValue({
      ...tenant,
      connectors: { health: true, claims: true },
    });
    const user = await loadWith();

    await user.click(await screen.findByRole("button", { name: "claims · off" }));
    expect(api.toggleConnector).toHaveBeenCalledWith(tenant.tenant_id, "claims", true);
    expect(await screen.findByRole("button", { name: "claims · on" })).toBeEnabled();
  });

  it("keeps the tenant unchanged and reports a failed toggle", async () => {
    api.toggleConnector.mockRejectedValue(new Error("toggle failed (500)"));
    const user = await loadWith();

    await user.click(await screen.findByRole("button", { name: "health · on" }));
    expect(api.toggleConnector).toHaveBeenCalledWith(tenant.tenant_id, "health", false);
    expect(await screen.findByText("toggle failed (500)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "health · on" })).toBeEnabled();
  });
});
