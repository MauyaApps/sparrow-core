# sparrow-core

Transfer layer of Sparrow: CPace (ristretto255 + SHA-512), HKDF, XChaCha20-Poly1305 and the transfer protocol (`docs/protocol.md`).
Pure TypeScript on audited `@noble/*` libraries. Runs in Node 22+, browsers and Termux.

```ts
import { sendVault, receiveVault, wsConnect } from "./src/index.js";

// sender (host): shows a QR or code, then sends
await sendVault(vaultBytes, {
  connect: wsConnect(["https://relay.example"]), relays: ["https://relay.example"],
  mode: "code", ui: { onShow: ({ code }) => console.log("Code:", code) },
});

// receiver (guest): scans the QR text or types the code
const vault = await receiveVault({ code: "1234567" }, { connect: wsConnect(["https://relay.example"]) });
```

Tests: `npm install && npm test`. Against a real relay: `RELAY=https://relay.example npm test`.
