// Offline end-to-end test: every variant runs unmodified against a local
// mock of the two Adyen endpoints, so no API key or test-env card is needed.
//
// The mock unwraps the session key with the RSA private key in BigInt
// arithmetic — Node's own crypto.privateDecrypt() has had RSAES-PKCS1-v1_5
// disabled by default since CVE-2023-46809 (the Marvin attack) — validates
// the RFC 8017 §7.2.1 padding, and answers like the real reveal endpoint.
//
// Expected outcome, mirroring the Adyen test environment: the three
// RSAES-PKCS1-v1_5 variants reveal the card; reveal-webcrypto.js is rejected
// with "Invalid session key".

import { execFile } from "node:child_process";
import http from "node:http";

const CARD_DETAILS = {
  pan: "5555444430644664",
  expiration: { month: "05", year: "2026" },
  cvc: "846",
};

const bytesToHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex) =>
  Uint8Array.from(hex.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));

const modPow = (base, exponent, modulus) => {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
};

// A fresh RSA-2048 keypair standing in for Adyen's panReveal key.
const keyPair = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt"],
);
const publicKeyBase64 = Buffer.from(
  await crypto.subtle.exportKey("spki", keyPair.publicKey),
).toString("base64");
const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
const n = BigInt(`0x${Buffer.from(jwk.n, "base64url").toString("hex")}`);
const d = BigInt(`0x${Buffer.from(jwk.d, "base64url").toString("hex")}`);

/** RSAES-PKCS1-v1_5 decryption per RFC 8017 §7.2.2. Throws on bad padding. */
const unwrapSessionKey = (encryptedKeyHex) => {
  const em = hexToBytes(
    modPow(BigInt(`0x${encryptedKeyHex}`), d, n)
      .toString(16)
      .padStart(512, "0"),
  );
  const separator = em.indexOf(0x00, 2);
  if (em[0] !== 0x00 || em[1] !== 0x02 || separator < 10) {
    throw new Error("Invalid RSAES-PKCS1-v1_5 padding.");
  }
  const sessionKey = em.subarray(separator + 1);
  if (sessionKey.length !== 32) throw new Error("Not an AES-256 key.");
  return sessionKey;
};

const server = http.createServer(async (request, response) => {
  const respond = (status, body) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  };
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);

  if (request.method === "GET" && request.url.startsWith("/bcl/v2/publicKey")) {
    respond(200, { publicKey: publicKeyBase64 });
    return;
  }
  if (
    request.method === "POST" &&
    request.url === "/bcl/v2/paymentInstruments/reveal"
  ) {
    const { encryptedKey } = JSON.parse(Buffer.concat(chunks).toString());
    let sessionKey;
    try {
      sessionKey = unwrapSessionKey(encryptedKey);
    } catch {
      respond(400, {
        type: "https://docs.adyen.com/errors/bad-request",
        title: "Bad request",
        status: 400,
        detail: "Invalid session key",
        errorCode: "00_400",
      });
      return;
    }
    const aesKey = await crypto.subtle.importKey(
      "raw",
      sessionKey,
      { name: "AES-CBC" },
      false,
      ["encrypt"],
    );
    const encryptedData = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: new Uint8Array(16) },
        aesKey,
        new TextEncoder().encode(JSON.stringify(CARD_DETAILS)),
      ),
    );
    respond(200, { encryptedData: bytesToHex(encryptedData) });
    return;
  }
  respond(404, { detail: `Unexpected request: ${request.method} ${request.url}` });
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

const runVariant = (file) =>
  new Promise((resolve) =>
    execFile(
      process.execPath,
      [file],
      {
        env: {
          ...process.env,
          ADYEN_API_BASE: `http://127.0.0.1:${server.address().port}/bcl/v2`,
          ADYEN_API_KEY: "offline-test",
          PAYMENT_INSTRUMENT_ID: "PI_OFFLINE_TEST",
        },
      },
      (error, stdout, stderr) => resolve({ error, stdout, stderr }),
    ),
  );

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? "ok  " : "FAIL"}  ${name}`);
  if (!ok) {
    failures++;
    console.log(detail.replace(/^/gm, "      "));
  }
};

for (const file of ["reveal-forge.js", "reveal-micro.js", "reveal-diy.js"]) {
  const { error, stdout, stderr } = await runVariant(file);
  check(
    `${file} reveals the card`,
    !error && stdout.includes(CARD_DETAILS.pan),
    stderr || stdout,
  );
}

const { error, stderr } = await runVariant("reveal-webcrypto.js");
check(
  "reveal-webcrypto.js is rejected (endpoint accepts no RSA-OAEP)",
  Boolean(error) && stderr.includes("Invalid session key"),
  stderr,
);

server.close();
process.exit(failures === 0 ? 0 : 1);
