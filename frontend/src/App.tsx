import { useState } from "react";
import AdminConsole from "./components/admin/AdminConsole";
import DrivePanel from "./components/DrivePanel";
import ResearchPortal from "./components/research/ResearchPortal";
import { brand } from "./config/brand";

type View = "drive" | "research" | "admin";

export default function App() {
  const [view, setView] = useState<View>("drive");

  const tab = (id: View, label: string) => (
    <button
      type="button"
      onClick={() => setView(id)}
      className={`rounded-lg px-3 py-1.5 text-sm ${
        view === id
          ? "bg-slate-800 text-slate-100"
          : "text-slate-400 hover:text-slate-200"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold">{brand.publicName}</h1>
          <p className="text-xs font-semibold uppercase tracking-widest text-emerald-400">
            End-to-end encrypted drive
          </p>
        </div>
        <nav className="flex gap-1">
          {tab("drive", "Drive")}
          {tab("research", "Research")}
          {tab("admin", "Admin")}
        </nav>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 p-6">
        {view === "drive" ? <DrivePanel /> : view === "research" ? <ResearchPortal /> : <AdminConsole />}
      </main>

      <footer className="px-6 py-4 text-xs text-slate-600">
        {brand.features.zkEnabled ? "ZK features enabled" : "ZK features disabled"} · Files are
        encrypted on your device before upload; {brand.domainName} stores ciphertext only.
      </footer>
    </div>
  );
}
