import { useCallback, useEffect, useRef, useState } from "react";
import { DriveWorkerClient } from "../lib/crypto/workerClient";
import type { DriveFileSummary, InitResult } from "../lib/crypto/protocol";
import { errorMessage } from "../lib/format";
import DropZone from "./DropZone";
import FileList from "./FileList";
import KeySetupGate from "./KeySetupGate";

const ACK_STORAGE_KEY = "key-isolation-acknowledged";

interface Transfer {
  key: string;
  name: string;
  done: number;
  total: number;
}

type Phase = "loading" | "gate" | "ready" | "failed";

export default function DrivePanel() {
  const clientRef = useRef<DriveWorkerClient | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [info, setInfo] = useState<InitResult | null>(null);
  const [files, setFiles] = useState<DriveFileSummary[]>([]);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [busyIds, setBusyIds] = useState<ReadonlySet<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const client = () => {
    clientRef.current ??= new DriveWorkerClient();
    return clientRef.current;
  };

  const refresh = useCallback(async () => {
    setFiles(await client().list());
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await client().init();
        if (cancelled) return;
        setInfo(result);
        const acknowledged = localStorage.getItem(ACK_STORAGE_KEY) === "1";
        setPhase(result.created && !acknowledged ? "gate" : "ready");
        await refresh();
      } catch (err) {
        if (!cancelled) {
          setError(errorMessage(err, "failed to initialize keys"));
          setPhase("failed");
        }
      }
    })();
    return () => {
      cancelled = true;
      clientRef.current?.terminate();
      clientRef.current = null;
    };
  }, [refresh]);

  const markBusy = (objectId: string, busy: boolean) => {
    setBusyIds((prev) => {
      const next = new Set(prev);
      if (busy) next.add(objectId);
      else next.delete(objectId);
      return next;
    });
  };

  const upload = (dropped: File[]) => {
    for (const file of dropped) {
      const key = `${file.name}-${crypto.randomUUID()}`;
      setTransfers((prev) => [...prev, { key, name: file.name, done: 0, total: 1 }]);
      client()
        .upload(file, (done, total) => {
          setTransfers((prev) =>
            prev.map((t) => (t.key === key ? { ...t, done, total } : t)),
          );
        })
        .then(refresh)
        .catch((err: unknown) => {
          setError(errorMessage(err, "upload failed"));
        })
        .finally(() => {
          setTransfers((prev) => prev.filter((t) => t.key !== key));
        });
    }
  };

  const download = async (objectId: string) => {
    markBusy(objectId, true);
    setError(null);
    try {
      const { summary, blob } = await client().download(objectId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = summary.name;
      anchor.click();
      // Revoking synchronously can cancel the download in some browsers.
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err) {
      setError(errorMessage(err, "download failed"));
    } finally {
      markBusy(objectId, false);
    }
  };

  const remove = async (objectId: string) => {
    markBusy(objectId, true);
    setError(null);
    try {
      await client().remove(objectId);
      await refresh();
    } catch (err) {
      setError(errorMessage(err, "delete failed"));
    } finally {
      markBusy(objectId, false);
    }
  };

  if (phase === "loading") {
    return <p className="py-16 text-center text-sm text-slate-500">Preparing your keys…</p>;
  }

  if (phase === "failed") {
    return (
      <p className="py-16 text-center text-sm text-rose-300">
        Could not initialize device keys{error ? `: ${error}` : ""}. This browser may not
        support the required Web Crypto features.
      </p>
    );
  }

  if (phase === "gate" && info) {
    return (
      <KeySetupGate
        info={info}
        onAcknowledge={() => {
          localStorage.setItem(ACK_STORAGE_KEY, "1");
          setPhase("ready");
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {info?.fingerprint && (
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span>Device key</span>
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-emerald-300">
            {info.fingerprint}
          </span>
          <span>· keys never leave this device</span>
        </div>
      )}

      <DropZone onFiles={upload} />

      {transfers.length > 0 && (
        <div className="space-y-2">
          {transfers.map((t) => (
            <div key={t.key} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
              <div className="flex justify-between text-xs text-slate-300">
                <span className="truncate">{t.name}</span>
                <span>
                  encrypting {t.done}/{t.total}
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded bg-slate-800">
                <div
                  className="h-full bg-emerald-500 transition-all"
                  style={{ width: `${t.total === 0 ? 100 : Math.round((t.done / t.total) * 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {error && (
        <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </p>
      )}

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4">
        <FileList files={files} busyIds={busyIds} onDownload={download} onDelete={remove} />
      </div>
    </div>
  );
}
