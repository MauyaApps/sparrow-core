// CPace (draft-irtf-cfrg-cpace) with ristretto255 + SHA-512.
// Checked against the official test vectors in test/cpace.test.ts.
import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concatBytes, equalBytes, randomBytes, utf8ToBytes } from "./bytes.js";

const Point = ristretto255.Point;
const DSI = utf8ToBytes("CPaceRistretto255");
const ISK_DSI = utf8ToBytes("CPaceRistretto255_ISK");
const S_IN_BYTES = 128; // SHA-512 input block size

export function prependLen(data: Uint8Array): Uint8Array {
  let n = data.length;
  const len: number[] = [];
  for (;;) {
    len.push(n < 128 ? n : (n & 0x7f) + 0x80);
    n >>= 7;
    if (n === 0) break;
  }
  return concatBytes(Uint8Array.from(len), data);
}

export function lvCat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts.map(prependLen));
}

export function calculateGenerator(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array) {
  const zpad = Math.max(0, S_IN_BYTES - prependLen(prs).length - prependLen(DSI).length - 1);
  const genStr = lvCat(DSI, prs, new Uint8Array(zpad), ci, sid);
  return ristretto255_hasher.deriveToCurve!(sha512(genStr));
}

function scalarFromBytes(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function sampleScalar(): bigint {
  for (;;) {
    const b = randomBytes(32);
    b[31] &= 0x0f; // keep 252 bits, as recommended by the draft
    const s = scalarFromBytes(b);
    if (s !== 0n) return s;
  }
}

export interface CPaceOptions {
  prs: Uint8Array; // password-related string
  ci: Uint8Array; // channel / party identifiers
  sid: Uint8Array; // session id both sides agree on in advance
  ad?: Uint8Array; // associated data sent with our share (default empty)
  scalar?: Uint8Array; // fixed secret scalar (little endian), for test vectors only
}

export class CPaceAbort extends Error {}

export class CPace {
  readonly message: Uint8Array; // our public share Y (32 bytes)
  private readonly y: bigint;
  private readonly ad: Uint8Array;
  private done = false;

  constructor(
    private readonly role: "initiator" | "responder",
    private readonly o: CPaceOptions,
  ) {
    this.ad = o.ad ?? new Uint8Array(0);
    this.y = o.scalar ? scalarFromBytes(o.scalar) : sampleScalar();
    const g = calculateGenerator(o.prs, o.ci, o.sid);
    this.message = g.multiply(this.y).toBytes();
  }

  /** Takes the peer's share, returns the 64-byte intermediate session key (ISK). */
  finish(peerShare: Uint8Array, peerAd: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (this.done) throw new CPaceAbort("already finished");
    this.done = true;
    let K: Uint8Array;
    try {
      const peer = Point.fromBytes(peerShare);
      const k = peer.multiply(this.y);
      if (k.is0()) throw new CPaceAbort("identity");
      K = k.toBytes();
    } catch (e) {
      throw e instanceof CPaceAbort ? e : new CPaceAbort("invalid point");
    }
    const [ya, ada, yb, adb] =
      this.role === "initiator"
        ? [this.message, this.ad, peerShare, peerAd]
        : [peerShare, peerAd, this.message, this.ad];
    const transcript = concatBytes(lvCat(ya, ada), lvCat(yb, adb));
    return sha512(concatBytes(lvCat(ISK_DSI, this.o.sid, K), transcript));
  }
}

export { equalBytes };
