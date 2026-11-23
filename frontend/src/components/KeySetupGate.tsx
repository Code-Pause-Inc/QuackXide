import { useState } from "react";
import { brand } from "../config/brand";
import type { InitResult } from "../lib/crypto/protocol";

interface KeySetupGateProps {
  info: InitResult;
  onAcknowledge: () => void;
}

/** First-run briefing, gated on explicit acknowledgement: losing these keys
 *  means losing the data, and users must know that before storing anything. */
export default function KeySetupGate({ info, onAcknowledge }: KeySetupGateProps) {
  const [accepted, setAccepted] = useState(false);

  if (info.enrollment === "refused") return <SecondDeviceRefusal />;

  return (
    <div className="mx-auto max-w-xl rounded-2xl border border-slate-800 bg-slate-900/60 p-8">
      <p className="text-xs font-semibold uppercase tracking-widest text-emerald-400">
        Your keys are ready
      </p>
      <h2 className="mt-2 text-2xl font-semibold text-slate-100">
        Encryption keys were generated on this device
      </h2>

      {info.fingerprint && (
        <p className="mt-4 text-sm text-slate-400">
          Device key fingerprint:{" "}
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-emerald-300">
            {info.fingerprint}
          </span>
        </p>
      )}

      <ul className="mt-6 space-y-3 text-sm text-slate-300">
        <li className="flex gap-3">
          <span aria-hidden className="text-emerald-400">✓</span>
          Your master key was created here and is <strong>non-extractable</strong> — it is never
          sent to {brand.domainName} or anyone else.
        </li>
        <li className="flex gap-3">
          <span aria-hidden className="text-emerald-400">✓</span>
          Files are encrypted before upload; the service stores ciphertext it cannot read.
        </li>
        <li className="flex gap-3">
          <span aria-hidden className="text-amber-400">!</span>
          <span>
            <strong>If you lose this device or clear this browser&apos;s site data, your files
            cannot be recovered by anyone — including {brand.publicName} support.</strong>
          </span>
        </li>
      </ul>

      {!info.hpkeKeyAvailable && (
        <p className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
          This browser could not load the encryption module for your data key, so it cannot
          receive sealed research results yet. Drive encryption works fully. When the module
          loads in a later session, a data key is added to this device automatically and your
          existing files stay readable.
        </p>
      )}

      <label className="mt-6 flex cursor-pointer items-start gap-3 text-sm text-slate-300">
        <input
          type="checkbox"
          checked={accepted}
          onChange={(ev) => setAccepted(ev.target.checked)}
          className="mt-0.5"
        />
        I understand my keys exist only on this device and that losing them means my encrypted
        files are permanently unrecoverable.
      </label>

      <button
        type="button"
        disabled={!accepted}
        onClick={onAcknowledge}
        className="mt-6 w-full rounded-xl bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
      >
        Open my encrypted drive
      </button>
    </div>
  );
}

/** Shown when the account already has a different key enrolled. In v1 a
 *  key lives on one device and is never replaced silently (ADR 0004), so a
 *  second device or a cleared browser is refused rather than re-keyed. */
function SecondDeviceRefusal() {
  return (
    <div
      role="alert"
      className="mx-auto max-w-xl rounded-2xl border border-rose-500/40 bg-slate-900/60 p-8"
    >
      <p className="text-xs font-semibold uppercase tracking-widest text-rose-400">
        This device cannot be used
      </p>
      <h2 className="mt-2 text-2xl font-semibold text-slate-100">
        Your account&apos;s keys are on another device
      </h2>
      <ul className="mt-6 space-y-3 text-sm text-slate-300">
        <li>
          Your account already has an encryption key, created on the device or browser you first
          used. Keys stay on that device and are never copied to {brand.domainName}.
        </li>
        <li>
          To keep your data safe, a new device cannot replace that key. Open your drive on the
          original device and browser instead.
        </li>
        <li>
          If you cleared this browser&apos;s site data, the original key is gone and{" "}
          {brand.publicName} cannot recover it. Using more than one device and replacing a lost
          key are not supported in this version.
        </li>
      </ul>
    </div>
  );
}
