// Base64 is used only at display and HTTP boundaries; in-memory and
// IndexedDB records keep raw ArrayBuffers.

/** Bytes per String.fromCharCode call, to stay under argument-count limits. */
const B64_STEP = 0x8000;

export function toB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += B64_STEP) {
    bin += String.fromCharCode(...bytes.subarray(i, i + B64_STEP));
  }
  return btoa(bin);
}

export function fromB64(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out.buffer;
}
