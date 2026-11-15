import { test } from "node:test";
import assert from "node:assert/strict";
import { hexToBytes as unhex, bytesToHex } from "@noble/hashes/utils.js";
import { CPace, CPaceAbort, calculateGenerator } from "../src/cpace.js";

// Official CPace test vectors, ristretto255 + SHA-512 (draft-irtf-cfrg-cpace, testvectors.json "G_Coffee25519")
const V = {
  PRS: "50617373776F7264",
  CI: "0B415F696E69746961746F720B425F726573706F6E646572",
  sid: "7E4B4791D6A8EF019B936C79FB7F2C57",
  g: "222B6B195FE84B1652BADB6F6A3AE3D24341E7306967F0B8115B40D5698C7E56",
  ya: "DA3D23700A9E5699258AEF94DC060DFDA5EBB61F02A5EA77FAD53F4FF0976D08",
  ADa: "414461",
  Ya: "D6BAC480F2C386C394EFC7C47ADB9925DCD2630B64F240C50F8D0EEC482B9157",
  yb: "D2316B454718C35362D83D69DF6320F38578ED5984651435E2949762D900B80D",
  ADb: "414462",
  Yb: "3EA7E0B19560D7C0B0F5734F63B955286DFA8232B5EBE63324E2D9E7433F7258",
  ISK_IR:
    "B69EFFBF61B51D56401C0F65601ABE428DE8206FEAAF0E32198896DCAE7B35CD2B38950A39DFD5D4A79164614C2984F7DAA460B588C1E80C3FA2068AF7900447",
  invalidY1: "2B3C6B8C4F3800E7AEF6864025B4ED79BD599117E427C41BD47D93D654B4A51C",
  invalidY2: "0000000000000000000000000000000000000000000000000000000000000000",
};
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const opts = { prs: unhex(V.PRS), ci: unhex(V.CI), sid: unhex(V.sid) };

test("generator matches the official vector", () => {
  assert.equal(up(calculateGenerator(opts.prs, opts.ci, opts.sid).toBytes()), V.g);
});

test("public shares match the official vectors", () => {
  assert.equal(up(new CPace("initiator", { ...opts, scalar: unhex(V.ya) }).message), V.Ya);
  assert.equal(up(new CPace("responder", { ...opts, scalar: unhex(V.yb) }).message), V.Yb);
});

test("ISK matches the official vector (both roles)", () => {
  const a = new CPace("initiator", { ...opts, ad: unhex(V.ADa), scalar: unhex(V.ya) });
  const b = new CPace("responder", { ...opts, ad: unhex(V.ADb), scalar: unhex(V.yb) });
  assert.equal(up(a.finish(unhex(V.Yb), unhex(V.ADb))), V.ISK_IR);
  assert.equal(up(b.finish(unhex(V.Ya), unhex(V.ADa))), V.ISK_IR);
});

test("invalid point and identity are rejected", () => {
  const a = () => new CPace("initiator", { ...opts });
  assert.throws(() => a().finish(unhex(V.invalidY1)), CPaceAbort);
  assert.throws(() => a().finish(unhex(V.invalidY2)), CPaceAbort);
  assert.throws(() => a().finish(new Uint8Array(5)), CPaceAbort);
});

test("random run: same password agrees, different password does not", () => {
  const run = (p1: string, p2: string) => {
    const mk = (r: "initiator" | "responder", p: string) =>
      new CPace(r, { prs: new TextEncoder().encode(p), ci: opts.ci, sid: opts.sid });
    const a = mk("initiator", p1), b = mk("responder", p2);
    return [up(a.finish(b.message)), up(b.finish(a.message))];
  };
  const same = run("1234", "1234");
  assert.equal(same[0], same[1]);
  const diff = run("1234", "1235");
  assert.notEqual(diff[0], diff[1]);
});
