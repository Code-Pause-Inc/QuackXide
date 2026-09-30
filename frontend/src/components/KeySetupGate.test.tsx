import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { brand } from "../config/brand";
import type { InitResult } from "../lib/crypto/protocol";
import KeySetupGate from "./KeySetupGate";

const info: InitResult = {
  created: true,
  tenantId: "6f2c8a2e-1111-4222-8333-444455556666",
  x25519Supported: true,
  hpkePublicKeyB64: "AAAA",
  fingerprint: "ab12-cd34-ef56-7890",
};

describe("KeySetupGate", () => {
  it("requires the acknowledgement before opening the drive", async () => {
    const user = userEvent.setup();
    const onAcknowledge = vi.fn();
    render(<KeySetupGate info={info} onAcknowledge={onAcknowledge} />);

    const open = screen.getByRole("button", { name: /open my encrypted drive/i });
    expect(open).toBeDisabled();

    await user.click(screen.getByRole("checkbox"));
    expect(open).toBeEnabled();
    await user.click(open);
    expect(onAcknowledge).toHaveBeenCalledOnce();
  });

  it("shows the device fingerprint and the configured brand", () => {
    render(<KeySetupGate info={info} onAcknowledge={vi.fn()} />);
    expect(screen.getByText(info.fingerprint!)).toBeInTheDocument();
    expect(
      screen.getByText(new RegExp(`including ${brand.publicName} support`)),
    ).toBeInTheDocument();
    expect(screen.queryByText(/does not support X25519/)).not.toBeInTheDocument();
  });

  it("warns when X25519 is unavailable", () => {
    render(
      <KeySetupGate
        info={{ ...info, x25519Supported: false, hpkePublicKeyB64: null, fingerprint: null }}
        onAcknowledge={vi.fn()}
      />,
    );
    expect(screen.getByText(/does not support X25519/)).toBeInTheDocument();
    expect(screen.queryByText(/fingerprint/i)).not.toBeInTheDocument();
  });
});
