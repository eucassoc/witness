// Anchoring and passkey signatures: the two things the operator's service,
// the witness and the page all have to agree on.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import * as t from '../public/deedlog.js';
import { challengeFor, verifyAssertion } from '../public/webauthn.js';
import { passkey } from './passkey.mjs';

const hex = (n) => randomBytes(n).toString('hex');

/** `k` records of a chain, as lines and as the bodies their subject digests are of. */
function records(k, name = 'log.example/dlm/records') {
  const lines = [];
  const bodies = [];
  for (let i = 0; i < k; i++) {
    const r = t.makeRecord(t.readChain(lines), { name, source: { type: 'test', id: name, collector: 'test' }, event: 'thing.happened', meta: { item: hex(16) } });
    lines.push(r.line);
    bodies.push(r.body);
  }
  return { lines, bodies };
}

test('what a record is about leads to its interval\'s commitment, and to no other', () => {
  for (const k of [0, 1, 2, 3, 4, 5, 8, 9, 31]) {
    const { lines, bodies } = records(k);
    const terms = { chain: 'log.example/dlm/records', epoch: '2026-11-19T03:20:00Z', nonce: hex(16), pad: hex(16) };
    const a = t.anchor(lines, terms);
    assert.equal(a.size, k <= 1 ? 1 : 2 ** Math.ceil(Math.log2(k)), `${k} records fill a tree of a power of two`);
    bodies.forEach((body, i) => {
      const at = t.recordProof(lines, i, { seq: 7, ...terms });
      assert.deepEqual([at.seq, at.epoch, at.size, at.index], [7, terms.epoch, a.size, i]);
      assert.equal(t.commitOf(body, terms.chain, at), a.commit);
      assert.notEqual(t.commitOf(body + ' ', terms.chain, at), a.commit, 'something else');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, epoch: '2026-11-19T03:30:00Z' }), a.commit, 'another interval');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, nonce: hex(16) }), a.commit, 'another nonce');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, blind: hex(32) }), a.commit, 'another blind');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, record: hex(32) }), a.commit, 'another record');
      if (a.size > 1) assert.notEqual(t.commitOf(body, terms.chain, { ...at, index: (i + 1) % a.size }), a.commit, 'another place');
      // What is handed over says nothing of the record's place in the chain.
      assert.deepEqual(Object.keys(at).sort(), ['blind', 'epoch', 'index', 'nonce', 'path', 'record', 'seq', 'size']);
      assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ['at', 'event', 'item']);
    });
    // A line changed anywhere but in what it is about still changes the commitment.
    if (k) assert.notEqual(t.anchor([lines[0].replace('"type":"test"', '"type":"tess"'), ...lines.slice(1)], terms).commit, a.commit);
  }
});

test('an interval with nothing in it looks like any other', () => {
  const terms = (epoch) => ({ chain: 'c', epoch, nonce: hex(16), pad: hex(16) });
  const a = t.anchor([], terms('2026-11-19T03:20:00Z'));
  const b = t.anchor([], terms('2026-11-19T03:30:00Z'));
  assert.equal(a.size, 1);
  assert.notEqual(a.commit, b.commit);
  assert.match(a.commit, /^[0-9a-f]{64}$/);
});

test('a passkey\'s signature is checked against the key, the challenge and the site', async () => {
  const origin = 'https://witness.example';
  const key = await passkey({ origin });
  const statement = JSON.stringify({ type: 'audit-statement/v1', origin: 'log.example/dlm', at: '2026-11-19T03:25:00Z', findings: { overdue: 0 } });
  const challenge = challengeFor(statement);
  const credential = await key.sign(challenge);
  const ok = await verifyAssertion({ key: key.entry.key, credential, challenge, origin, rpId: 'witness.example' });
  assert.equal(ok.userVerified, true);
  const refuse = (what, args) => assert.rejects(verifyAssertion({ key: key.entry.key, credential, challenge, origin, rpId: 'witness.example', ...args }), undefined, what);
  await refuse('another statement', { challenge: challengeFor(statement + ' ') });
  await refuse('another site', { origin: 'https://evil.example' });
  await refuse('another relying party', { rpId: 'evil.example' });
  await refuse('another key', { key: (await passkey({ origin })).entry.key });
  await refuse('a registration, not a signature', { credential: await key.sign(challenge, { type: 'webauthn.create' }) });
  await refuse('nobody there', { credential: await key.sign(challenge, { present: false }) });
  await refuse('made at another site', { credential: await key.sign(challenge, { at: 'https://evil.example' }) });
  // Many signatures: the encoding of r and s varies in length.
  for (let i = 0; i < 40; i++) await verifyAssertion({ key: key.entry.key, credential: await key.sign(challenge), challenge, origin, rpId: 'witness.example' });
});
