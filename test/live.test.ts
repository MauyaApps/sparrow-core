// Runs against a real relay:  RELAY=https://host npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { bigRandom } from "./helpers.js";
import { receiveVault, sendVault, wsConnect } from "../src/index.js";

const RELAY = process.env.RELAY;

for (const mode of ["qr", "code"] as const) {
  test(`live relay: ${mode} transfer of 600 KB`, { skip: !RELAY }, async () => {
    const connect = wsConnect([RELAY!]);
    const data = bigRandom(600_000);
    let show!: (v: string) => void;
    const shown = new Promise<string>((r) => (show = r));
    const sender = sendVault(data, { connect, relays: [RELAY!], mode, ui: { onShow: (i) => show((i.qr ?? i.code)!) } });
    const text = await shown;
    const got = await receiveVault(mode === "qr" ? { qr: text } : { code: text }, { connect });
    await sender;
    assert.deepEqual(got, data);
  });
}
