import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AccessRequestView,
  BudgetView,
  CatalogView,
  GrantView,
  ListingView,
} from "../../lib/research/client";
import ResearchPortal from "./ResearchPortal";

const api = vi.hoisted(() => ({
  constructed: vi.fn(),
  catalog: vi.fn(),
  grants: vi.fn(),
  budget: vi.fn(),
  myRequests: vi.fn(),
  requestAccess: vi.fn(),
  publishListing: vi.fn(),
  withdrawListing: vi.fn(),
  approveRequest: vi.fn(),
  denyRequest: vi.fn(),
  topUpBudget: vi.fn(),
  revokeGrant: vi.fn(),
}));

vi.mock("../../lib/research/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/research/client")>()),
  ResearchClient: class {
    constructor(baseUrl: string, token: string) {
      api.constructed(baseUrl, token);
    }
    catalog = api.catalog;
    grants = api.grants;
    budget = api.budget;
    myRequests = api.myRequests;
    requestAccess = api.requestAccess;
    publishListing = api.publishListing;
    withdrawListing = api.withdrawListing;
    approveRequest = api.approveRequest;
    denyRequest = api.denyRequest;
    topUpBudget = api.topUpBudget;
    revokeGrant = api.revokeGrant;
  },
}));

const ME = "aaaaaaaa-1111-4222-8333-444455556666";
const STEWARD = "bbbbbbbb-1111-4222-8333-444455556666";
const RESEARCHER = "cccccccc-1111-4222-8333-444455556666";
const TOKEN = `e30.${btoa(JSON.stringify({ tid: ME }))}.sig`;
const RAW_ROW = "patient-7731,1962-04-18,E11.9";
const STAMP = "2026-07-30T10:00:00.000Z";

function listing(
  listing_id: string,
  steward_tenant: string,
  connector: string,
  title: string,
): ListingView {
  return {
    listing_id,
    steward_tenant,
    connector,
    title,
    description: `${title} description`,
    license_fee_cents: 120_000,
    compute_rate_cents: 40,
    grant_budget: 50,
    published: true,
    created_at_iso: STAMP,
    updated_at_iso: STAMP,
  };
}

function grant(
  grant_id: string,
  steward_tenant: string,
  researcher_tenant: string,
  connector: string,
): GrantView {
  return {
    grant_id,
    steward_tenant,
    researcher_tenant,
    connector,
    revoked: false,
    created_at_iso: STAMP,
    updated_at_iso: STAMP,
  };
}

function request(
  request_id: string,
  target: ListingView,
  researcher_tenant: string,
  status: AccessRequestView["status"],
  note = "",
): AccessRequestView {
  return {
    request_id,
    listing_id: target.listing_id,
    steward_tenant: target.steward_tenant,
    researcher_tenant,
    connector: target.connector,
    note,
    status,
    created_at_iso: STAMP,
    updated_at_iso: STAMP,
  };
}

const authorizedListing = listing("l-auth", STEWARD, "claims", "Claims aggregates");
const pendingListing = listing("l-pending", STEWARD, "labs", "Lab panels");
const deniedListing = listing("l-denied", STEWARD, "imaging", "Imaging metadata");
const openListing = listing("l-open", STEWARD, "survey", "Survey responses");
const ownListing = listing("l-own", ME, "health", "Outcomes registry");

const myGrant = grant("g-mine", STEWARD, ME, "claims");
const issuedGrant = grant("g-issued", ME, RESEARCHER, "health");
const unmeteredGrant = grant("g-unmetered", ME, RESEARCHER, "other");

const catalog: CatalogView = {
  currency: "USD",
  listings: [authorizedListing, pendingListing, deniedListing, openListing, ownListing],
};

// Unexpected fields must never reach the page, whatever the API returns.
const leakyCatalog = { ...catalog, rows: [RAW_ROW], sample: RAW_ROW } as CatalogView;

const budgets: Record<string, BudgetView> = {
  "g-mine": { grant_id: "g-mine", limit: 50, spent: 12, remaining: 38 },
  "g-issued": { grant_id: "g-issued", limit: 20, spent: 5, remaining: 15 },
};

function seed() {
  api.catalog.mockResolvedValue(leakyCatalog);
  api.grants.mockResolvedValue([myGrant, issuedGrant, unmeteredGrant]);
  api.budget.mockImplementation(async (grantId: string) => {
    const budget = budgets[grantId];
    if (!budget) throw new Error("budget standing: not found");
    return { ...budget, rows: [RAW_ROW] };
  });
  api.myRequests.mockResolvedValue([
    request("r-pending", pendingListing, ME, "pending"),
    request("r-denied", deniedListing, ME, "denied"),
    request("r-incoming", ownListing, RESEARCHER, "pending", "IRB-2026-114"),
  ]);
}

async function openPortal() {
  const user = userEvent.setup();
  render(<ResearchPortal />);
  const input = screen.getByPlaceholderText(/bearer jwt/i);
  await user.clear(input);
  await user.click(input);
  await user.paste(TOKEN);
  await user.click(screen.getByRole("button", { name: "Open portal" }));
  return user;
}

function catalogItem(title: string) {
  const section = within(screen.getByRole("heading", { name: "Dataset catalog" }).parentElement!);
  return within(section.getByText(title).closest("li")!);
}

describe("ResearchPortal", () => {
  beforeEach(seed);

  it("requires a token and shows nothing before connecting", () => {
    render(<ResearchPortal />);
    expect(screen.getByRole("button", { name: "Open portal" })).toBeDisabled();
    expect(screen.queryByText("Research data access")).not.toBeInTheDocument();
  });

  it("shows a loading state while the portal loads", async () => {
    api.catalog.mockReturnValue(new Promise(() => {}));
    await openPortal();
    expect(screen.getByRole("button", { name: "Loading…" })).toBeDisabled();
    expect(api.constructed).toHaveBeenCalledWith(expect.any(String), TOKEN);
  });

  it("shows the client's error message and no data when loading fails", async () => {
    api.catalog.mockRejectedValue(new Error("research access is not enabled on this deployment"));
    await openPortal();
    expect(
      await screen.findByText("research access is not enabled on this deployment"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Research data access")).not.toBeInTheDocument();
  });

  it("shows the empty states", async () => {
    api.catalog.mockResolvedValue({ currency: "USD", listings: [] });
    api.grants.mockResolvedValue([]);
    api.myRequests.mockResolvedValue([]);
    await openPortal();
    expect(await screen.findByText(/none yet/i)).toBeInTheDocument();
    expect(screen.getByText("No datasets are currently published.")).toBeInTheDocument();
    expect(screen.getByText(/nothing published/i)).toBeInTheDocument();
    expect(screen.queryByText("Access requests")).not.toBeInTheDocument();
    expect(screen.queryByText("Issued access")).not.toBeInTheDocument();
  });

  it("states the aggregate-only and suppression guarantees", async () => {
    await openPortal();
    expect(
      await screen.findByText(/small cohorts are suppressed before release/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/aggregate-only queries · small-cohort suppression/i),
    ).toBeInTheDocument();
  });

  it("shows query allowances, and marks unavailable ones", async () => {
    await openPortal();
    expect(await screen.findByText("38 of 50 queries left")).toBeInTheDocument();
    expect(screen.getByText("5 of 20 queries used")).toBeInTheDocument();
    expect(screen.getByText("allowance unavailable")).toBeInTheDocument();
  });

  it("never renders dataset rows returned alongside the view", async () => {
    await openPortal();
    await screen.findByText("Research data access");
    expect(document.body.textContent).not.toContain(RAW_ROW);
  });

  it("shows each catalog listing's price and access state", async () => {
    await openPortal();
    await screen.findByText("Research data access");

    expect(catalogItem("Claims aggregates").getByText("Access active")).toBeInTheDocument();
    expect(catalogItem("Claims aggregates").getByText("$1,200")).toBeInTheDocument();
    expect(catalogItem("Claims aggregates").getByText("$0.40 / query")).toBeInTheDocument();
    expect(catalogItem("Lab panels").getByText("Pending")).toBeInTheDocument();
    expect(catalogItem("Imaging metadata").getByText("Declined")).toBeInTheDocument();
    expect(
      catalogItem("Imaging metadata").getByRole("button", { name: "Request again" }),
    ).toBeInTheDocument();
    expect(
      catalogItem("Survey responses").getByRole("button", { name: "Request access" }),
    ).toBeInTheDocument();
    expect(catalogItem("Outcomes registry").getByText("Your dataset")).toBeInTheDocument();
  });

  it("requests access with a trimmed note and reloads", async () => {
    api.requestAccess.mockResolvedValue(request("r-new", openListing, ME, "pending"));
    const user = await openPortal();
    await screen.findByText("Research data access");

    await user.click(
      catalogItem("Survey responses").getByRole("button", { name: "Request access" }),
    );
    const note = screen.getByPlaceholderText(/purpose of access/i);
    expect(note).toHaveAttribute("maxLength", "1000");
    await user.type(note, "  IRB-2026-200 ");
    await user.click(screen.getByRole("button", { name: "Submit request" }));

    expect(api.requestAccess).toHaveBeenCalledExactlyOnceWith("l-open", "IRB-2026-200");
    expect(api.catalog).toHaveBeenCalledTimes(2);
    expect(screen.queryByPlaceholderText(/purpose of access/i)).not.toBeInTheDocument();
  });

  it("keeps the request open and shows the error when it fails", async () => {
    api.requestAccess.mockRejectedValue(new Error("this dataset is no longer available"));
    const user = await openPortal();
    await screen.findByText("Research data access");

    await user.click(
      catalogItem("Survey responses").getByRole("button", { name: "Request access" }),
    );
    await user.click(screen.getByRole("button", { name: "Submit request" }));

    expect(await screen.findByText("this dataset is no longer available")).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/purpose of access/i)).toBeInTheDocument();
  });

  it("lets a steward review incoming requests", async () => {
    api.approveRequest.mockResolvedValue({});
    api.denyRequest.mockRejectedValue(new Error("decline failed (409)"));
    const user = await openPortal();

    const incoming = within((await screen.findByText("“IRB-2026-114”")).closest("li")!);
    expect(incoming.getByText(/researcher cccccccc/)).toBeInTheDocument();

    await user.click(incoming.getByRole("button", { name: "Approve" }));
    expect(api.approveRequest).toHaveBeenCalledWith("r-incoming");

    await user.click(incoming.getByRole("button", { name: "Decline" }));
    expect(api.denyRequest).toHaveBeenCalledWith("r-incoming");
    expect(await screen.findByText("decline failed (409)")).toBeInTheDocument();
  });

  it("publishes a listing from the stewardship panel and closes the form", async () => {
    api.publishListing.mockResolvedValue(ownListing);
    const user = await openPortal();

    await user.click(await screen.findByRole("button", { name: "Publish a dataset" }));
    await user.type(screen.getByPlaceholderText(/connector slug/), "survey");
    await user.type(screen.getByPlaceholderText(/listing title/), "Survey waves");
    await user.type(screen.getByPlaceholderText(/license fee/), "100");
    await user.type(screen.getByPlaceholderText(/rate per query/), "0.25");
    await user.click(screen.getByRole("button", { name: "Publish listing" }));

    expect(api.publishListing).toHaveBeenCalledWith({
      connector: "survey",
      title: "Survey waves",
      description: "",
      license_fee_cents: 10_000,
      compute_rate_cents: 25,
    });
    expect(await screen.findByRole("button", { name: "Publish a dataset" })).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/connector slug/)).not.toBeInTheDocument();
  });

  it("tops up and revokes issued access", async () => {
    api.topUpBudget.mockResolvedValue(budgets["g-issued"]);
    api.revokeGrant.mockResolvedValue(issuedGrant);
    const user = await openPortal();

    const issued = within((await screen.findByText("5 of 20 queries used")).closest("li")!);
    const add = issued.getByRole("button", { name: "Add" });
    expect(add).toBeDisabled();
    await user.type(issued.getByPlaceholderText("+ queries"), "10");
    await user.click(add);
    expect(api.topUpBudget).toHaveBeenCalledWith("g-issued", 10);

    await user.click(issued.getByRole("button", { name: "Revoke" }));
    expect(api.revokeGrant).not.toHaveBeenCalled();
    await user.click(issued.getByRole("button", { name: "Confirm revoke" }));
    expect(api.revokeGrant).toHaveBeenCalledWith("g-issued");
  });
});
