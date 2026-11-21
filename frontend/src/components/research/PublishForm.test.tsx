import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ConnectorView } from "../../lib/research/client";
import PublishForm from "./PublishForm";

const TITLE_MAX = 120;
const DESCRIPTION_MAX = 2000;

const CONNECTORS: ConnectorView[] = [
  {
    slug: "quickbooks",
    display_name: "QuickBooks",
    kind: "accounting",
    columns: [
      { name: "id", type: "string" },
      { name: "total", type: "float64" },
    ],
  },
  {
    slug: "odoo",
    display_name: "Odoo",
    kind: "erp",
    columns: [{ name: "is_company", type: "boolean" }],
  },
  { slug: "research_extract", display_name: "Research Extract", kind: "health", columns: [] },
];

function setup(busy = false, connectors: ConnectorView[] = []) {
  const user = userEvent.setup();
  const onPublish = vi.fn();
  render(
    <PublishForm busy={busy} currency="USD" connectors={connectors} onPublish={onPublish} />,
  );
  const field = (placeholder: RegExp) => screen.getByPlaceholderText(placeholder);
  const inputs = {
    connector: field(/connector slug/),
    title: field(/listing title/),
    description: field(/description/),
    fee: field(/license fee \(USD\)/),
    rate: field(/rate per query \(USD\)/),
    queries: field(/included queries/),
  };
  const fill = async (values: Partial<Record<keyof typeof inputs, string>>) => {
    for (const [key, value] of Object.entries(values)) {
      const input = inputs[key as keyof typeof inputs];
      await user.clear(input);
      if (value) {
        await user.click(input);
        await user.paste(value);
      }
    }
  };
  const publish = () => screen.getByRole("button", { name: /publish/i });
  return { user, onPublish, inputs, fill, publish };
}

/** The dictionary editor's column names, in order. */
function columnNames(): string[] {
  return screen
    .queryAllByRole("textbox", { name: /^Column \d+ name$/ })
    .map((input) => (input as HTMLInputElement).value);
}

const valid = { connector: "health", title: "Cohort outcomes", fee: "$1,200", rate: "0.40" };

describe("PublishForm", () => {
  it("stays disabled until the required fields are valid", async () => {
    const { fill, publish } = setup();
    expect(publish()).toBeDisabled();
    await fill(valid);
    expect(publish()).toBeEnabled();
  });

  it("publishes a trimmed body with amounts in cents and no default budget", async () => {
    const { user, fill, publish, onPublish } = setup();
    await fill({
      ...valid,
      connector: "  health  ",
      title: "  Cohort outcomes ",
      description: " Aggregates ",
    });
    await user.click(publish());
    expect(onPublish).toHaveBeenCalledExactlyOnceWith({
      connector: "health",
      title: "Cohort outcomes",
      description: "Aggregates",
      license_fee_cents: 120_000,
      compute_rate_cents: 40,
      data_dictionary: { columns: [] },
    });
  });

  it("includes an explicit query allowance", async () => {
    const { user, fill, publish, onPublish } = setup();
    await fill({ ...valid, queries: "25" });
    await user.click(publish());
    expect(onPublish).toHaveBeenCalledWith(expect.objectContaining({ grant_budget: 25 }));
  });

  it.each([
    ["an uppercase slug", { connector: "Health" }],
    ["a slug with spaces", { connector: "health data" }],
    ["a slug over 64 characters", { connector: "a".repeat(65) }],
    ["a blank title", { title: "   " }],
    ["a fee with three decimals", { fee: "1.234" }],
    ["a negative fee", { fee: "-5" }],
    ["a non-numeric rate", { rate: "free" }],
    ["a fractional allowance", { queries: "2.5" }],
    ["a negative allowance", { queries: "-1" }],
  ])("rejects %s", async (_, override) => {
    const { fill, publish } = setup();
    await fill({ ...valid, ...override });
    expect(publish()).toBeDisabled();
  });

  it("accepts a 64-character slug and a zero allowance", async () => {
    const { fill, publish } = setup();
    await fill({ ...valid, connector: "a".repeat(64), queries: "0" });
    expect(publish()).toBeEnabled();
  });

  it("caps the title and description lengths", async () => {
    const { fill, inputs } = setup();
    expect(inputs.title).toHaveAttribute("maxLength", String(TITLE_MAX));
    expect(inputs.description).toHaveAttribute("maxLength", String(DESCRIPTION_MAX));

    await fill({ title: "t".repeat(TITLE_MAX + 10) });
    expect(inputs.title).toHaveValue("t".repeat(TITLE_MAX));
  });

  it("disables publishing while busy", async () => {
    const { fill, publish } = setup(true);
    await fill(valid);
    expect(publish()).toHaveTextContent("Publishing…");
    expect(publish()).toBeDisabled();
  });

  it("pre-fills a connector dataset's columns and publishes them as edited", async () => {
    const { user, fill, publish, onPublish } = setup(false, CONNECTORS);
    await fill({ ...valid, connector: "quickbooks" });
    expect(columnNames()).toEqual(["id", "total"]);
    expect(screen.getByRole("combobox", { name: "Column 2 type" })).toHaveValue("float64");
    expect(screen.getByText(/Pre-filled from the QuickBooks connector/)).toBeInTheDocument();

    await user.click(screen.getByRole("textbox", { name: "Column 2 description" }));
    await user.paste("  Invoice total, in dollars ");
    await user.click(publish());
    expect(onPublish).toHaveBeenCalledWith(
      expect.objectContaining({
        connector: "quickbooks",
        data_dictionary: {
          columns: [
            { name: "id", type: "string", description: "" },
            { name: "total", type: "float64", description: "Invoice total, in dollars" },
          ],
        },
      }),
    );
  });

  it("follows the dataset until the steward edits the columns", async () => {
    const { user, fill } = setup(false, CONNECTORS);
    await fill({ connector: "quickbooks" });
    expect(columnNames()).toEqual(["id", "total"]);
    await fill({ connector: "odoo" });
    expect(columnNames()).toEqual(["is_company"]);
    // No mapper, or not a connector: the steward enters the columns.
    for (const dataset of ["research_extract", "upload_cohorts"]) {
      await fill({ connector: dataset });
      expect(columnNames()).toEqual([]);
      expect(screen.getByText(/Describe the columns researchers can query/)).toBeInTheDocument();
    }
    await fill({ connector: "quickbooks" });
    expect(columnNames()).toEqual(["id", "total"]);

    // Once edited, the columns stay when the dataset changes, and the
    // connector's own can be put back.
    await user.type(screen.getByRole("textbox", { name: "Column 1 name" }), "_x");
    await fill({ connector: "odoo" });
    expect(columnNames()).toEqual(["id_x", "total"]);
    await user.click(screen.getByRole("button", { name: "Use the Odoo connector’s columns" }));
    expect(columnNames()).toEqual(["is_company"]);
    expect(
      screen.queryByRole("button", { name: /connector’s columns/ }),
    ).not.toBeInTheDocument();
  });

  it("takes an upload's columns by hand", async () => {
    const { user, fill, publish, onPublish } = setup(false, CONNECTORS);
    await fill({ ...valid, connector: "upload_cohorts" });
    const add = screen.getByRole("button", { name: "Add column" });
    await user.click(add);
    await user.click(add);
    await user.click(add);
    await user.type(screen.getByRole("textbox", { name: "Column 1 name" }), "condition");
    await user.type(screen.getByRole("textbox", { name: "Column 1 description" }), "Diagnosis");
    await user.type(screen.getByRole("textbox", { name: "Column 2 name" }), "First Name");
    await user.type(screen.getByRole("textbox", { name: "Column 3 name" }), "age");
    await user.selectOptions(screen.getByRole("combobox", { name: "Column 3 type" }), "int64");
    await user.click(screen.getByRole("button", { name: "Remove column 2" }));
    expect(columnNames()).toEqual(["condition", "age"]);

    await user.click(publish());
    expect(onPublish).toHaveBeenCalledWith(
      expect.objectContaining({
        data_dictionary: {
          columns: [
            { name: "condition", type: "string", description: "Diagnosis" },
            { name: "age", type: "int64", description: "" },
          ],
        },
      }),
    );
  });

  it("refuses a dictionary the API would refuse, and says why", async () => {
    const { user, fill, publish } = setup();
    await fill(valid);
    await user.click(screen.getByRole("button", { name: "Add column" }));
    expect(publish()).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("Column 1 needs a name");

    await user.type(screen.getByRole("textbox", { name: "Column 1 name" }), "age");
    expect(publish()).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Add column" }));
    await user.type(screen.getByRole("textbox", { name: "Column 2 name" }), "age");
    expect(publish()).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("Column 2 repeats the name “age”");

    const second = screen.getByRole("textbox", { name: "Column 2 name" });
    await user.clear(second);
    await user.click(second);
    await user.paste("x".repeat(129));
    expect(publish()).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("Column 2 needs a name of 1 to 128 bytes");
    expect(
      screen.getByRole("textbox", { name: "Column 1 description" }),
    ).toHaveAttribute("maxLength", "500");
  });
});
