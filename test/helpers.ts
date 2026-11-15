import { SparrowError, type Connect, type Incoming, type Link } from "../src/transfer.js";

class MemLink implements Link {
  queue: Incoming[] = [];
  waiter: { res: (m: Incoming) => void; rej: (e: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;
  closed = false;
  peer?: MemLink;
  onClose?: () => void;
  tap?: (d: Uint8Array) => Uint8Array;

  push(m: Incoming) {
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      clearTimeout(w.timer);
      w.res(m);
    } else this.queue.push(m);
  }
  send(d: Uint8Array) {
    const out = this.tap ? this.tap(d) : d;
    this.peer?.push({ data: new Uint8Array(out) });
  }
  recv(ms: number): Promise<Incoming> {
    const q = this.queue.shift();
    if (q) return Promise.resolve(q);
    if (this.closed) return Promise.reject(new SparrowError("ended"));
    return new Promise((res, rej) => {
      const timer = setTimeout(() => { this.waiter = null; rej(new SparrowError("timeout")); }, ms);
      this.waiter = { res, rej, timer };
    });
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      clearTimeout(w.timer);
      w.rej(new SparrowError("ended"));
    }
    this.onClose?.();
  }
}

/** A tiny in-memory model of the relay: same rules, no network. */
export function memoryRelay(opts: { tamper?: (d: Uint8Array, from: "host" | "guest") => Uint8Array } = {}) {
  const sessions = new Map<string, { host: MemLink; guest?: MemLink; joins: number }>();
  const connect: Connect = async (kind, id, role) => {
    const key = `${kind}:${id}`;
    const link = new MemLink();
    if (role === "host") {
      if (sessions.has(key)) throw new SparrowError("connect", "taken");
      sessions.set(key, { host: link, joins: 0 });
      link.onClose = () => {
        const s = sessions.get(key);
        s?.guest?.push({ text: "session-ended" });
        s?.guest?.close();
        sessions.delete(key);
      };
      if (opts.tamper) link.tap = (d) => opts.tamper!(d, "host");
      return link;
    }
    const s = sessions.get(key);
    if (!s || s.guest || s.joins >= 3) throw new SparrowError("connect", "refused");
    s.joins++;
    s.guest = link;
    link.peer = s.host;
    s.host.peer = link;
    link.onClose = () => { s.host.push({ text: "peer-left" }); s.guest = undefined; };
    if (opts.tamper) link.tap = (d) => opts.tamper!(d, "guest");
    s.host.push({ text: "peer-joined" });
    return link;
  };
  return { connect, sessions };
}

/** Random bytes of any size (crypto.getRandomValues is limited to 64 KiB per call). */
export function bigRandom(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
}
