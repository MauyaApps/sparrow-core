import { CPace, lvCat } from "./cpace.js";
import { b64urlDecode, b64urlEncode, concatBytes, randomBytes, utf8ToBytes } from "./bytes.js";
import { FrameError, MAX_CHUNK, T, deriveKeys, open, pakeFrame, readPakeFrame, seal, type Keys } from "./frames.js";

export type ErrorCode = "handshake" | "timeout" | "ended" | "protocol" | "connect" | "aborted";
export class SparrowError extends Error {
  constructor(readonly code: ErrorCode, message?: string) {
    super(message ?? code);
  }
}

export type Incoming = { text: string } | { data: Uint8Array };
/** One connected side of a relay session. Text frames come from the relay, binary frames from the peer. */
export interface Link {
  send(data: Uint8Array): void;
  recv(timeoutMs: number): Promise<Incoming>;
  close(): void;
}
export type Connect = (kind: "session" | "code", id: string, role: "host" | "guest") => Promise<Link>;

export interface HostUi {
  /** Show the QR text (qr mode) or the 7-digit code (code mode) to the user. */
  onShow(info: { qr?: string; code?: string }): void;
  /** Optional: show the 4-digit check string, return false if the user says it does not match. */
  confirmSas?(sas: string): Promise<boolean>;
}
export interface GuestUi {
  confirmSas?(sas: string): Promise<boolean>;
}

const DEFAULT_TIMEOUT = 120_000;
const CI = lvCat(utf8ToBytes("sparrow/v1"), utf8ToBytes("host"), utf8ToBytes("guest"));

// ---------- QR payload ----------
export function buildQr(id: Uint8Array, key: Uint8Array, relays: string[]): string {
  const r = relays.map((x) => "r=" + encodeURIComponent(x)).join("&");
  return `sparrow://t/1/${b64urlEncode(id)}/${b64urlEncode(key)}?${r}`;
}

export function parseQr(text: string): { id: Uint8Array; key: Uint8Array; relays: string[] } {
  const m = /^sparrow:\/\/t\/1\/([A-Za-z0-9_-]{22})\/([A-Za-z0-9_-]{43})\?(.*)$/.exec(text.trim());
  if (!m) throw new SparrowError("protocol", "not a Sparrow QR");
  const relays = m[3].split("&").filter((p) => p.startsWith("r=")).map((p) => decodeURIComponent(p.slice(2)));
  return { id: b64urlDecode(m[1]), key: b64urlDecode(m[2]), relays };
}

// ---------- helpers ----------
type Clock = { deadline: number };
const left = (c: Clock) => Math.max(1, c.deadline - Date.now());

async function recvBin(link: Link, c: Clock): Promise<Uint8Array> {
  for (;;) {
    const m = await link.recv(left(c));
    if ("data" in m) return m.data;
    if (m.text === "session-ended" || m.text === "peer-left") throw new SparrowError("ended");
  }
}

async function waitPeer(link: Link, c: Clock): Promise<void> {
  for (;;) {
    const m = await link.recv(left(c));
    if ("text" in m) {
      if (m.text === "peer-joined") return;
      if (m.text === "session-ended") throw new SparrowError("ended");
    }
  }
}

async function guard<T>(link: Link, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    try { link.close(); } catch { /* ignore */ }
    if (e instanceof SparrowError) throw e;
    if (e instanceof FrameError) throw new SparrowError("protocol", e.message);
    throw e;
  }
}

async function senderPhase(link: Link, k: Keys, payload: Uint8Array, ui: HostUi, c: Clock): Promise<void> {
  const hello = await recvBin(link, c);
  try {
    if (open(k, hello).type !== T.HELLO) throw new FrameError("expected HELLO");
  } catch {
    throw new SparrowError("handshake", "peer does not hold the same key or code");
  }
  link.send(seal(k, T.READY));
  if (ui.confirmSas && !(await ui.confirmSas(k.sas))) {
    link.send(seal(k, T.ERROR, Uint8Array.of(1)));
    throw new SparrowError("aborted", "check string rejected");
  }
  for (let off = 0; off === 0 || off < payload.length; off += MAX_CHUNK) {
    const chunk = payload.subarray(off, off + MAX_CHUNK);
    const last = off + MAX_CHUNK >= payload.length ? 1 : 0;
    link.send(seal(k, T.DATA, concatBytes(Uint8Array.of(last), chunk)));
  }
  const ack = open(k, await recvBin(link, c));
  if (ack.type === T.ERROR) throw new SparrowError("aborted", "receiver aborted");
  if (ack.type !== T.ACK) throw new SparrowError("protocol", "expected ACK");
  link.close();
}

async function receiverPhase(link: Link, k: Keys, ui: GuestUi, c: Clock): Promise<Uint8Array> {
  link.send(seal(k, T.HELLO));
  let ready;
  try {
    ready = open(k, await recvBin(link, c));
  } catch (e) {
    // The sender closes the session when it cannot decrypt our HELLO.
    if (e instanceof SparrowError && e.code === "ended") throw new SparrowError("handshake", "wrong code, or session ended");
    throw new SparrowError("handshake", "wrong code or tampered data");
  }
  if (ready.type !== T.READY) throw new SparrowError("protocol", "expected READY");
  if (ui.confirmSas && !(await ui.confirmSas(k.sas))) {
    link.send(seal(k, T.ERROR, Uint8Array.of(1)));
    throw new SparrowError("aborted", "check string rejected");
  }
  const parts: Uint8Array[] = [];
  for (;;) {
    const m = open(k, await recvBin(link, c));
    if (m.type === T.ERROR) throw new SparrowError("aborted", "sender aborted");
    if (m.type !== T.DATA || m.body.length < 1) throw new SparrowError("protocol", "expected DATA");
    parts.push(m.body.subarray(1));
    if (m.body[0] & 1) break;
  }
  link.send(seal(k, T.ACK));
  link.close();
  return concatBytes(...parts);
}

// ---------- public API ----------
export interface SendOptions {
  connect: Connect;
  relays: string[]; // written into the QR so the other device knows where to go
  mode: "qr" | "code";
  ui: HostUi;
  timeoutMs?: number;
}

/** The device that has the data shows a QR / code (host) and sends. */
export async function sendVault(payload: Uint8Array, o: SendOptions): Promise<void> {
  const c = { deadline: Date.now() + (o.timeoutMs ?? DEFAULT_TIMEOUT) };
  if (o.mode === "qr") {
    const id = randomBytes(16);
    const key = randomBytes(32);
    const link = await o.connect("session", b64urlEncode(id), "host");
    return guard(link, async () => {
      o.ui.onShow({ qr: buildQr(id, key, o.relays) });
      await waitPeer(link, c);
      await senderPhase(link, deriveKeys(key, id, "host"), payload, o.ui, c);
    });
  }

  let link: Link | undefined;
  let plate = "";
  for (let i = 0; i < 8 && !link; i++) {
    plate = String(randomBytes(2).reduce((a, b) => (a << 8) | b, 0) % 1000).padStart(3, "0");
    try {
      link = await o.connect("code", plate, "host");
    } catch { /* number in use or relay refused: try another */ }
  }
  if (!link) throw new SparrowError("connect", "could not reserve a code");
  const l = link;
  return guard(l, async () => {
    const secret = String(randomBytes(2).reduce((a, b) => (a << 8) | b, 0) % 10000).padStart(4, "0");
    o.ui.onShow({ code: plate + secret });
    await waitPeer(l, c);
    const sid = utf8ToBytes(plate);
    const pake = new CPace("initiator", { prs: utf8ToBytes(secret), ci: CI, sid });
    l.send(pakeFrame(pake.message));
    const isk = pake.finish(readPakeFrame(await recvBin(l, c)));
    await senderPhase(l, deriveKeys(isk, sid, "host"), payload, o.ui, c);
  });
}

export interface ReceiveOptions {
  connect: Connect;
  ui?: GuestUi;
  timeoutMs?: number;
}

/** The device that scans the QR or types the 7-digit code (guest) and receives. */
export async function receiveVault(
  target: { qr: string } | { code: string },
  o: ReceiveOptions,
): Promise<Uint8Array> {
  const c = { deadline: Date.now() + (o.timeoutMs ?? DEFAULT_TIMEOUT) };
  const ui = o.ui ?? {};
  if ("qr" in target) {
    const { id, key } = parseQr(target.qr);
    const link = await o.connect("session", b64urlEncode(id), "guest");
    return guard(link, () => receiverPhase(link, deriveKeys(key, id, "guest"), ui, c));
  }
  const m = /^(\d{3})(\d{4})$/.exec(target.code.replace(/[\s-]/g, ""));
  if (!m) throw new SparrowError("protocol", "code must be 7 digits");
  const [, plate, secret] = m;
  const link = await o.connect("code", plate, "guest");
  return guard(link, async () => {
    const sid = utf8ToBytes(plate);
    const pake = new CPace("responder", { prs: utf8ToBytes(secret), ci: CI, sid });
    const peerShare = readPakeFrame(await recvBin(link, c));
    link.send(pakeFrame(pake.message));
    const isk = pake.finish(peerShare);
    return receiverPhase(link, deriveKeys(isk, sid, "guest"), ui, c);
  });
}
