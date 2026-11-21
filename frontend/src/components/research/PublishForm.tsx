import { useState } from "react";
import {
  type ConnectorView,
  dollarsToCents,
  type PublishListingBody,
} from "../../lib/research/client";
import {
  type DictionaryColumn,
  connectorPrefill,
  dictionaryProblem,
  sameColumns,
} from "../../lib/research/dictionary";
import DictionaryEditor from "./DictionaryEditor";
import { inputCls, primaryBtnCls } from "./styles";

const CONNECTOR_SLUG = /^[a-z0-9_-]{1,64}$/;
const TITLE_MAX = 120;
const DESCRIPTION_MAX = 2000;

/** Publishes (or re-publishes) a priced dataset listing with its data
 *  dictionary. A connector dataset's dictionary starts from the columns its
 *  connector's mapper writes; any other dataset's is entered by hand. */
export default function PublishForm({
  busy,
  currency,
  connectors = [],
  onPublish,
}: {
  busy: boolean;
  currency: string;
  /** The built-in connectors and their columns (`GET /api/v1/connectors`). */
  connectors?: ConnectorView[];
  onPublish: (body: PublishListingBody) => void;
}) {
  const [connector, setConnector] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [fee, setFee] = useState("");
  const [rate, setRate] = useState("");
  const [queries, setQueries] = useState("");
  const [columns, setColumns] = useState<DictionaryColumn[]>([]);

  const prefill = connectorPrefill(connectors, connector.trim());
  /** Columns that are empty or still the pre-fill follow the dataset;
   *  once the steward edits them they stay. */
  const chooseDataset = (value: string) => {
    const untouched =
      columns.length === 0 || (prefill !== null && sameColumns(columns, prefill.columns));
    setConnector(value);
    if (untouched) setColumns(connectorPrefill(connectors, value.trim())?.columns ?? []);
  };

  const feeCents = dollarsToCents(fee);
  const rateCents = dollarsToCents(rate);
  const queriesNum = queries.trim() === "" ? undefined : Number(queries);
  const queriesOk =
    queriesNum === undefined || (Number.isInteger(queriesNum) && queriesNum >= 0);
  const connectorOk = CONNECTOR_SLUG.test(connector.trim());
  const ready =
    connectorOk &&
    title.trim().length > 0 &&
    title.trim().length <= TITLE_MAX &&
    feeCents !== null &&
    rateCents !== null &&
    queriesOk &&
    dictionaryProblem(columns) === null;

  return (
    <div className="mt-3 space-y-2 rounded-lg bg-slate-50 p-3 ring-1 ring-slate-100">
      <div className="grid grid-cols-2 gap-2">
        <input
          className={inputCls}
          value={connector}
          onChange={(ev) => chooseDataset(ev.target.value)}
          placeholder="dataset (connector slug, e.g. health)"
        />
        <input
          className={inputCls}
          value={title}
          onChange={(ev) => setTitle(ev.target.value)}
          maxLength={TITLE_MAX}
          placeholder="listing title"
        />
      </div>
      <input
        className={`${inputCls} w-full`}
        value={description}
        onChange={(ev) => setDescription(ev.target.value)}
        maxLength={DESCRIPTION_MAX}
        placeholder="description shown to researchers — optional"
      />
      <div className="grid grid-cols-3 gap-2">
        <input
          className={inputCls}
          value={fee}
          onChange={(ev) => setFee(ev.target.value)}
          placeholder={`license fee (${currency})`}
        />
        <input
          className={inputCls}
          value={rate}
          onChange={(ev) => setRate(ev.target.value)}
          placeholder={`rate per query (${currency})`}
        />
        <input
          className={inputCls}
          value={queries}
          onChange={(ev) => setQueries(ev.target.value)}
          placeholder="included queries (default)"
        />
      </div>
      <DictionaryEditor
        columns={columns}
        onChange={setColumns}
        source={prefill?.source ?? null}
        onUseSource={
          prefill && !sameColumns(columns, prefill.columns)
            ? () => setColumns(prefill.columns)
            : undefined
        }
      />
      <div className="flex justify-end">
        <button
          type="button"
          disabled={!ready || busy}
          onClick={() =>
            feeCents !== null &&
            rateCents !== null &&
            onPublish({
              connector: connector.trim(),
              title: title.trim(),
              description: description.trim(),
              license_fee_cents: feeCents,
              compute_rate_cents: rateCents,
              ...(queriesNum !== undefined ? { grant_budget: queriesNum } : {}),
              data_dictionary: {
                columns: columns.map((column) => ({
                  ...column,
                  description: column.description.trim(),
                })),
              },
            })
          }
          className={primaryBtnCls}
        >
          {busy ? "Publishing…" : "Publish listing"}
        </button>
      </div>
    </div>
  );
}
