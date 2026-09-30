import { useState } from "react";
import { shortId, type BudgetView, type GrantView } from "../../lib/research/client";
import { inputCls, primaryBtnCls, quietBtnCls } from "./styles";
import { Meter } from "./ui";

/** An issued grant with allowance meter, top-up, and two-step revoke. */
export default function IssuedGrantRow({
  grant,
  budget,
  title,
  busy,
  onTopUp,
  onRevoke,
}: {
  grant: GrantView;
  budget: BudgetView | undefined;
  title: string;
  busy: boolean;
  onTopUp: (grantId: string, additional: number) => void;
  onRevoke: (grantId: string) => void;
}) {
  const [topUp, setTopUp] = useState("");
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const topUpNum = Number(topUp);
  const topUpOk = topUp.trim() !== "" && Number.isInteger(topUpNum) && topUpNum > 0;

  return (
    <li className="flex items-center gap-4 py-4">
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{title}</p>
        <p className="mt-0.5 text-xs text-slate-500">
          researcher {shortId(grant.researcher_tenant)} · dataset {grant.connector}
        </p>
      </div>
      <div className="w-44">
        <p className="text-right text-xs tabular-nums text-slate-600">
          {budget ? `${budget.spent} of ${budget.limit} queries used` : "allowance unavailable"}
        </p>
        <div className="mt-1.5">
          <Meter spent={budget?.spent ?? 0} limit={budget?.limit ?? 0} />
        </div>
      </div>
      <div className="flex items-center gap-1.5">
        <input
          className={`${inputCls} w-20`}
          value={topUp}
          onChange={(ev) => setTopUp(ev.target.value)}
          placeholder="+ queries"
        />
        <button
          type="button"
          disabled={!topUpOk || busy}
          onClick={() => {
            onTopUp(grant.grant_id, topUpNum);
            setTopUp("");
          }}
          className={primaryBtnCls}
        >
          Add
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            if (confirmRevoke) onRevoke(grant.grant_id);
            setConfirmRevoke(!confirmRevoke);
          }}
          className={
            confirmRevoke
              ? "rounded-md bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
              : quietBtnCls
          }
        >
          {confirmRevoke ? "Confirm revoke" : "Revoke"}
        </button>
      </div>
    </li>
  );
}
