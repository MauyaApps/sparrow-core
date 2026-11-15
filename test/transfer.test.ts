import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "../src/bytes.js";
import { receiveVault, sendVault, SparrowError, parseQr } from "../src/transfer.js";
import { bigRandom, memoryRelay } from "./helpers.js";

const RELAYS = ["https://relay.example"];

async function run(mode: "qr" | "code", payload: Uint8Array, relay = memoryRelay(), edit?: (shown: string) => string) {
  const shown: { value?: string } = {};
  let resolveShown!: () => void;
  const ready = new Promise<void>((r) => (resolveShown = r));
  const sas: string[] = [];
  const sender = sendVault(payload, {
    connect: relay.connect, relays: RELAYS, mode, timeoutMs: 5000,
    ui: { onShow: (i) => { shown.value = i.qr ?? i.code; resolveShown(); }, confirmSas: async (s) => (sas.push(s), true) },
  });
  await ready;
  const text = edit ? edit(shown.value!) : shown.value!;
  const receiver = receiveVault(mode === "qr" ? { qr: text } : { code: text }, {
    connect: relay.connect, timeoutMs: 5000, ui: { confirmSas: async (s) => (sas.push(s), true) },
  });
  const [, got] = await Promise.all([sender, receiver]);
  return { got, sas, shown: shown.value! };
}

for (const mode of ["qr", "code"] as const) {
  test(`${mode}: transfers 700 KB (several chunks)`, async () => {
    const data = bigRandom(700_000);
    const r = await run(mode, data);
    assert.deepEqual(r.got, data);
    assert.equal(r.sas.length, 2);
    assert.equal(r.sas[0], r.sas[1]);
  });

  test(`${mode}: transfers an empty payload`, async () => {
    assert.equal((await run(mode, new Uint8Array(0))).got.length, 0);
  });
}

test("qr: the shown text parses and carries the relay list", async () => {
  const r = await run("qr", Uint8Array.of(1));
  assert.deepEqual(parseQr(r.shown).relays, RELAYS);
});

test("code: shown code is 7 digits", async () => {
  assert.match((await run("code", Uint8Array.of(1))).shown, /^\d{7}$/);
});

test("code: wrong secret digits fail on both sides", async () => {
  const relay = memoryRelay();
  const wrong = (c: string) => c.slice(0, 3) + String((Number(c.slice(3)) + 1) % 10000).padStart(4, "0");
  const shown: { v?: string } = {};
  let ready!: () => void;
  const p = new Promise<void>((r) => (ready = r));
  const sender = sendVault(Uint8Array.of(1, 2, 3), {
    connect: relay.connect, relays: RELAYS, mode: "code", timeoutMs: 3000,
    ui: { onShow: (i) => { shown.v = i.code; ready(); } },
  }).then(() => "ok", (e) => e);
  await p;
  const receiver = receiveVault({ code: wrong(shown.v!) }, { connect: relay.connect, timeoutMs: 3000 }).then(() => "ok", (e) => e);
  const [s, r] = await Promise.all([sender, receiver]);
  assert.ok(s instanceof SparrowError && s.code === "handshake", String(s));
  assert.ok(r instanceof SparrowError && r.code === "handshake", String(r));
  assert.equal(relay.sessions.size, 0); // host closed the session: one guess only
});

test("qr: a tampered DATA frame is detected", async () => {
  let n = 0;
  const relay = memoryRelay({
    tamper: (d, from) => {
      if (from === "host" && ++n === 2) { const x = d.slice(); x[x.length - 1] ^= 1; return x; } // 1st = READY, 2nd = DATA
      return d;
    },
  });
  await assert.rejects(run("qr", randomBytes(1000), relay), (e: unknown) => e instanceof SparrowError);
});

test("qr: user rejecting the check string aborts the transfer", async () => {
  const relay = memoryRelay();
  let ready!: () => void;
  const p = new Promise<void>((r) => (ready = r));
  const shown: { v?: string } = {};
  const sender = sendVault(Uint8Array.of(5), {
    connect: relay.connect, relays: RELAYS, mode: "qr", timeoutMs: 3000,
    ui: { onShow: (i) => { shown.v = i.qr; ready(); }, confirmSas: async () => true },
  }).then(() => "ok", (e) => e);
  await p;
  const receiver = receiveVault({ qr: shown.v! }, { connect: relay.connect, timeoutMs: 3000, ui: { confirmSas: async () => false } })
    .then(() => "ok", (e) => e);
  const [s, r] = await Promise.all([sender, receiver]);
  assert.ok(r instanceof SparrowError && r.code === "aborted");
  assert.ok(s instanceof SparrowError);
});

test("bad inputs are rejected early", async () => {
  const relay = memoryRelay();
  await assert.rejects(receiveVault({ code: "12345" }, { connect: relay.connect }), SparrowError);
  await assert.rejects(receiveVault({ qr: "hello" }, { connect: relay.connect }), SparrowError);
});
