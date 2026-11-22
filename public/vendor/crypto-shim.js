// What tsutome's reading half needs of node:crypto, for a browser: SHA-256
// as deedlog.js computes it. tsutome-core.js (generated) imports this in place
// of node:crypto.
import { concat, hex, sha256, utf8 } from '../deedlog.js';

export function createHash(algorithm) {
  if (algorithm !== 'sha256') throw new Error(`${algorithm} is not available here`);
  const parts = [];
  return {
    update(data) {
      parts.push(typeof data === 'string' ? utf8(data) : data);
      return this;
    },
    digest(encoding) {
      const d = sha256(concat(...parts));
      return encoding === 'hex' ? hex(d) : d;
    },
  };
}

export function createHmac() {
  throw new Error('HMAC is not available in the browser');
}
