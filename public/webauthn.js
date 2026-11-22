// Checking a passkey's signature (a WebAuthn assertion, ES256) with nothing
// but the platform's crypto, so that the same code runs in a Worker and in
// the browser of whoever wants to check a signed statement for themselves.
//
// What is signed is a challenge: for a login, a value the server made up;
// for a statement, the hash of the statement. The key is the passkey's
// public key as SubjectPublicKeyInfo, base64.
import { b64url, concat, equal, sha256, unb64, utf8 } from './deedlog.js';

export const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));

/** The challenge that stands for a statement: the hash of its bytes. */
export const challengeFor = (statement) => b64url(sha256(utf8(statement)));

/** An ECDSA signature as WebAuthn gives it (ASN.1 DER) to the 64 bytes Web Crypto takes. */
export function derToRaw(der) {
  const fail = () => {
    throw new Error('malformed signature');
  };
  if (der[0] !== 0x30) fail();
  let o = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
  const int = () => {
    if (der[o] !== 0x02) fail();
    const len = der[o + 1];
    let v = der.subarray(o + 2, o + 2 + len);
    o += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) fail();
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int();
  const s = int();
  return concat(r, s);
}

/**
 * Checks an assertion: that this key signed this challenge, for this site,
 * with the user present. `credential` holds `authenticatorData`,
 * `clientDataJSON` and `signature`, base64url. Throws with the reason.
 */
export async function verifyAssertion({ key, credential, challenge, origin, rpId }) {
  const clientData = unb64url(credential.clientDataJSON);
  let client;
  try {
    client = JSON.parse(new TextDecoder().decode(clientData));
  } catch {
    throw new Error('the client data is not JSON');
  }
  if (client.type !== 'webauthn.get') throw new Error('not a signature made by a passkey');
  if (client.challenge !== challenge) throw new Error('the signature is over something else');
  if (client.origin !== origin) throw new Error(`the signature was made at ${client.origin}, not at ${origin}`);
  const auth = unb64url(credential.authenticatorData);
  if (auth.length < 37) throw new Error('malformed authenticator data');
  if (!equal(auth.subarray(0, 32), sha256(utf8(rpId)))) throw new Error('the signature was made for another site');
  if (!(auth[32] & 0x01)) throw new Error('the user was not present');
  const spki = await crypto.subtle.importKey('spki', unb64(key), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, spki, derToRaw(unb64url(credential.signature)), concat(auth, sha256(clientData)));
  if (!ok) throw new Error('the signature does not verify with this key');
  return { userVerified: !!(auth[32] & 0x04), signCount: new DataView(auth.buffer, auth.byteOffset + 33, 4).getUint32(0) };
}
