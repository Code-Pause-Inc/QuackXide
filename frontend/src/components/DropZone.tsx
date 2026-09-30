import { useRef, useState, type DragEvent } from "react";

interface DropZoneProps {
  onFiles: (files: File[]) => void;
}

export default function DropZone({ onFiles }: DropZoneProps) {
  const [active, setActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const accept = (list: FileList | null) => {
    if (!list || list.length === 0) return;
    onFiles([...list]);
  };

  const onDrop = (ev: DragEvent<HTMLDivElement>) => {
    ev.preventDefault();
    setActive(false);
    accept(ev.dataTransfer.files);
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(ev) => {
        if (ev.key === "Enter" || ev.key === " ") inputRef.current?.click();
      }}
      onDragOver={(ev) => {
        ev.preventDefault();
        setActive(true);
      }}
      onDragLeave={() => setActive(false)}
      onDrop={onDrop}
      className={`flex min-h-40 cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-colors ${
        active
          ? "border-emerald-400 bg-emerald-400/10"
          : "border-slate-700 bg-slate-900/40 hover:border-slate-500"
      }`}
    >
      <p className="text-sm font-medium text-slate-200">
        Drop files here, or click to browse
      </p>
      <p className="mt-2 max-w-md text-xs text-slate-500">
        Each file is encrypted in this browser — inside an isolated worker,
        with a key that never leaves your device — before a single byte is
        stored.
      </p>
      <input
        ref={inputRef}
        type="file"
        multiple
        hidden
        onChange={(ev) => {
          accept(ev.target.files);
          ev.target.value = "";
        }}
      />
    </div>
  );
}
