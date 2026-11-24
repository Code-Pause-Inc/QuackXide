// The page headers the backend also sends, one `Name: value` line each in
// backend/crates/platform-api/page-headers.txt (one source of truth). Pure,
// so vite.config.ts and tests share it.

/** The headers in `text`, by the file's names. Throws on a line that is not
 *  `Name: value` or a name given twice. */
export function parsePageHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const seen = new Set<string>();
  for (const line of text.replace(/\n$/, "").split("\n")) {
    const at = line.indexOf(": ");
    if (at <= 0) throw new Error(`page-headers.txt: not a \`Name: value\` line: ${line}`);
    const name = line.slice(0, at);
    if (seen.has(name.toLowerCase())) throw new Error(`page-headers.txt: ${name} twice`);
    seen.add(name.toLowerCase());
    headers[name] = line.slice(at + 2);
  }
  return headers;
}
