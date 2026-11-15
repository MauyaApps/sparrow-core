import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveKeys, open, seal, T, FrameError, pakeFrame, readPakeFrame } from "../src/frames.js";

const ikm = new Uint8Array(32).fill(7);
const sid = new Uint8Array(16).fill(1);
const pair = () => [deriveKeys(ikm, sid, "host"), deriveKeys(ikm, sid, "guest")] as const;

test("round trip in both directions, SAS equal", () => {
  const [h, g] = pair();
  assert.equal(h.sas, g.sas);
  const body = Uint8Array.of(1, 2, 3);
  const m = open(g, seal(h, T.DATA, body));
  assert.equal(m.type, T.DATA);
  assert.deepEqual([...m.body], [1, 2, 3]);
  assert.equal(open(h, seal(g, T.ACK)).type, T.ACK);
});

test("tampering, wrong key, wrong session id are rejected", () => {
  const [h, g] = pair();
  const f = seal(h, T.DATA, Uint8Array.of(9));
  const bad = f.slice(); bad[bad.length - 1] ^= 1;
  assert.throws(() => open(g, bad), FrameError);
  const bad2 = f.slice(); bad2[1] = T.ACK; // type is authenticated
  assert.throws(() => open(g, bad2), FrameError);
  const other = deriveKeys(new Uint8Array(32).fill(8), sid, "guest");
  assert.throws(() => open(other, f), FrameError);
  const otherSid = deriveKeys(ikm, new Uint8Array(16).fill(2), "guest");
  assert.throws(() => open(otherSid, f), FrameError);
});

test("replay and reordering are rejected", () => {
  const [h, g] = pair();
  const f1 = seal(h, T.DATA, Uint8Array.of(1));
  const f2 = seal(h, T.DATA, Uint8Array.of(2));
  open(g, f2);
  assert.throws(() => open(g, f1), FrameError);
  assert.throws(() => open(g, f2), FrameError);
});

test("a host frame cannot be reflected back to the host", () => {
  const [h] = pair();
  assert.throws(() => open(h, seal(h, T.DATA)), FrameError);
});

test("PAKE frame length is strict", () => {
  assert.equal(readPakeFrame(pakeFrame(new Uint8Array(32))).length, 32);
  assert.throws(() => readPakeFrame(new Uint8Array(10)), FrameError);
});
