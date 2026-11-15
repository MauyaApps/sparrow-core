import { SparrowError, type Connect, type Incoming, type Link } from "./transfer.js";

function openWs(url: string): Promise<Link> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    const queue: Incoming[] = [];
    let waiter: { res: (m: Incoming) => void; rej: (e: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;
    let closed = false;
    let opened = false;

    ws.onmessage = (e) => {
      const m: Incoming = typeof e.data === "string" ? { text: e.data } : { data: new Uint8Array(e.data as ArrayBuffer) };
      if (waiter) {
        const w = waiter;
        waiter = null;
        clearTimeout(w.timer);
        w.res(m);
      } else queue.push(m);
    };
    ws.onclose = () => {
      closed = true;
      if (!opened) return reject(new SparrowError("connect"));
      if (waiter) {
        const w = waiter;
        waiter = null;
        clearTimeout(w.timer);
        w.rej(new SparrowError("ended"));
      }
    };
    ws.onerror = () => { if (!opened) reject(new SparrowError("connect")); };
    ws.onopen = () => {
      opened = true;
      resolve({
        send: (d) => ws.send(d),
        close: () => { try { ws.close(1000); } catch { /* ignore */ } },
        recv: (ms) => {
          const q = queue.shift();
          if (q) return Promise.resolve(q);
          if (closed) return Promise.reject(new SparrowError("ended"));
          return new Promise<Incoming>((res, rej) => {
            const timer = setTimeout(() => { waiter = null; rej(new SparrowError("timeout")); }, ms);
            waiter = { res, rej, timer };
          });
        },
      });
    };
  });
}

/** Opens sessions on the first relay in the list that answers. */
export function wsConnect(relays: string[]): Connect {
  return async (kind, id, role) => {
    for (const base of relays) {
      try {
        return await openWs(`${base.replace(/\/$/, "").replace(/^http/, "ws")}/v1/${kind}/${id}?role=${role}`);
      } catch { /* try the next relay */ }
    }
    throw new SparrowError("connect", "no relay reachable");
  };
}
