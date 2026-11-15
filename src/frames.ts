// Frame format: version(1) | type(1) | nonce(24) | ciphertext+tag
// Plaintext: seq (u32 BE) | body.   AAD: version | type | sid
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { concatBytes, randomBytes, readU32be, u32be, utf8ToBytes } from "./bytes.js";

export const VERSION = 1;
export const T = { HELLO: 1, READY: 2, DATA: 3, ACK: 4, ERROR: 5, PAKE: 0x10 } as const;
export const MAX_CHUNK = 256 * 1024;

export class FrameError extends Error {}

export interface Keys {
  sid: Uint8Array;
  send: Uint8Array;
  recv: Uint8Array;
  sas: string; // 4 digits both sides can compare
  sendSeq: number;
  recvSeq: number;
}

/** ikm is the QR key (32 bytes) or the PAKE output (64 bytes). */
export function deriveKeys(ikm: Uint8Array, sid: Uint8Array, role: "host" | "guest"): Keys {
  const d = (info: string, n = 32) => hkdf(sha256, ikm, sid, utf8ToBytes(info), n);
  const h2g = d("sparrow/v1/h2g");
  const g2h = d("sparrow/v1/g2h");
  const sasBytes = d("sparrow/v1/sas", 4);
  const sas = String(readU32be(sasBytes) % 10000).padStart(4, "0");
  return {
    sid,
    send: role === "host" ? h2g : g2h,
    recv: role === "host" ? g2h : h2g,
    sas,
    sendSeq: 0,
    recvSeq: -1,
  };
}

const aad = (type: number, sid: Uint8Array) => concatBytes(Uint8Array.of(VERSION, type), sid);

export function seal(k: Keys, type: number, body: Uint8Array = new Uint8Array(0)): Uint8Array {
  const nonce = randomBytes(24);
  const pt = concatBytes(u32be(k.sendSeq++), body);
  const ct = xchacha20poly1305(k.send, nonce, aad(type, k.sid)).encrypt(pt);
  return concatBytes(Uint8Array.of(VERSION, type), nonce, ct);
}

export function open(k: Keys, frame: Uint8Array): { type: number; body: Uint8Array } {
  if (frame.length < 2 + 24 + 16 + 4) throw new FrameError("short frame");
  if (frame[0] !== VERSION) throw new FrameError("unsupported version");
  const type = frame[1];
  let pt: Uint8Array;
  try {
    pt = xchacha20poly1305(k.recv, frame.subarray(2, 26), aad(type, k.sid)).decrypt(frame.subarray(26));
  } catch {
    throw new FrameError("decryption failed");
  }
  const seq = readU32be(pt, 0);
  if (seq <= k.recvSeq) throw new FrameError("replayed or reordered frame");
  k.recvSeq = seq;
  return { type, body: pt.subarray(4) };
}

export function pakeFrame(share: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(VERSION, T.PAKE), share);
}

export function readPakeFrame(frame: Uint8Array): Uint8Array {
  if (frame.length !== 34 || frame[0] !== VERSION || frame[1] !== T.PAKE) {
    throw new FrameError("bad PAKE frame");
  }
  return frame.subarray(2);
}
