import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import PublishForm from "./PublishForm";

const TITLE_MAX = 120;
const DESCRIPTION_MAX = 2000;

function setup(busy = false) {
  const user = userEvent.setup();
  const onPublish = vi.fn();
  render(<PublishForm busy={busy} currency="USD" onPublish={onPublish} />);
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
});
