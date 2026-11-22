// A passkey for tests: what an authenticator and a browser would produce
// between them, made with node's own crypto.
import { webcrypto } from 'node:crypto';
import { b64, b64url, concat, sha256, utf8 } from '../public/deedlog.js';

function rawToDer(raw) {
  const int = (v) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    v = v.subarray(i);
    if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

export async function passkey({ origin, rpId = new URL(origin).hostname, name = '内部監査室' }) {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const key = b64(new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)));
  const id = b64url(webcrypto.getRandomValues(new Uint8Array(16)));
  let count = 0;
  return {
    /** As it is registered: with the operator, and in the witness's registry. */
    entry: { name, id, key, alg: -7 },
    async sign(challenge, { type = 'webauthn.get', at = origin, present = true } = {}) {
      const clientDataJSON = utf8(JSON.stringify({ type, challenge, origin: at, crossOrigin: false }));
      const counter = new Uint8Array(4);
      new DataView(counter.buffer).setUint32(0, ++count);
      const authenticatorData = concat(sha256(utf8(rpId)), Uint8Array.of(present ? 0x05 : 0x00), counter);
      const raw = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, concat(authenticatorData, sha256(clientDataJSON))));
      return { id, authenticatorData: b64url(authenticatorData), clientDataJSON: b64url(clientDataJSON), signature: b64url(rawToDer(raw)) };
    },
  };
}
