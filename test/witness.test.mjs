// The witness with an in-memory store, as the Durable Object runs it.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as t from '../public/deedlog.js';
import { challengeFor } from '../public/webauthn.js';
import { Witness } from '../src/witness.js';
import { passkey } from './passkey.mjs';
import { MemoryStore } from './store.mjs';

const origin = 'log.example/test';
const source = { type: 'test', id: origin, collector: 'test' };
function grow(lines, n, event = 'thing.happened') {
  for (let i = 0; i < n; i++) lines.push(t.nextRecord(t.readChain(lines), { name: origin, source, event, meta: { item: String(lines.length) } }));
  return lines;
}
const leaves = (lines) => lines.map((l) => t.leafHash(l));

async function setup(env = {}) {
  const op = await t.generateKey(origin);
  const store = new MemoryStore();
  const registry = { witness: { name: 'witness.example' }, operators: [{ origin, checkpoint_key: op.vkey }, { origin: 'bad.example/log', checkpoint_key: 'nonsense' }] };
  const make = () => new Witness({ store, env, registry, now: () => new Date('2026-11-18T01:00:00Z') });
  const witness = make();
  const call = (w, method, path, body) => w.handle(new Request('https://witness.example' + path, { method, body }));
  const post = (w) => async (body) => {
    const r = await call(w, 'POST', '/add-checkpoint', body);
    return { status: r.status, body: await r.text(), type: r.headers.get('content-type') };
  };
  return { op, signer: await t.parseSigner(op.skey), store, make, witness, call, post };
}

test('cosigns a log in its registry, and keeps what it cosigned', async () => {
  const s = await setup();
  const vkeyRes = await s.call(s.witness, 'GET', '/witness.vkey');
  assert.equal(vkeyRes.headers.get('access-control-allow-origin'), '*');
  const vkey = (await vkeyRes.text()).trim();
  const w = t.parseVerifier(vkey);
  assert.equal(w.name, 'witness.example');
  assert.equal(w.typ, t.SIG_COSIGNATURE);

  const lines = grow([], 4);
  const note = await t.signCheckpoint(leaves(lines), s.signer);
  const got = await t.requestCosignature(note, leaves(lines), w, s.post(s.witness));
  const c = await t.verifyCheckpoint(note + got.lines.join(''), t.parseVerifier(s.op.vkey), [w], 1);
  assert.equal(c.cosigned[0].time, Date.parse('2026-11-18T01:00:00Z') / 1000);

  // A new instance over the same store (the Durable Object restarted): same key, same state.
  const again = s.make();
  assert.equal((await (await s.call(again, 'GET', '/witness.vkey')).text()).trim(), vkey);
  grow(lines, 5);
  const note2 = await t.signCheckpoint(leaves(lines), s.signer);
  const raw = await s.post(again)(`old 0\n\n${note2}`);
  assert.equal(raw.status, 409);
  assert.equal(raw.type, 'text/x.tlog.size');
  assert.equal(raw.body, '4\n');
  await t.requestCosignature(note2, leaves(lines), w, s.post(again), 0);

  const status = await (await s.call(again, 'GET', '/status.json')).json();
  assert.equal(status.witness, vkey);
  assert.deepEqual(status.logs[origin], { size: 9, root: t.b64(t.merkleRoot(leaves(lines))), time: Date.parse('2026-11-18T01:00:00Z') / 1000 });
});

test('refuses a rewritten history, an unknown log, a wrong key, and nonsense', async () => {
  const s = await setup();
  const post = s.post(s.witness);
  const lines = grow([], 6);
  assert.equal((await post(`old 0\n\n${await t.signCheckpoint(leaves(lines), s.signer)}`)).status, 200);

  const rewritten = grow([], 8, 'thing.rewritten');
  const forked = await t.signCheckpoint(leaves(rewritten), s.signer);
  const r = await post(`old 6\n${t.consistencyProof(leaves(rewritten), 6, 8).map((h) => t.b64(h) + '\n').join('')}\n${forked}`);
  assert.equal(r.status, 422);
  assert.equal((await (await s.call(s.witness, 'GET', '/status.json')).json()).logs[origin].size, 6);

  const stranger = await t.parseSigner((await t.generateKey('other.example/log')).skey);
  assert.equal((await post(`old 0\n\n${await t.signCheckpoint(leaves(lines), stranger)}`)).status, 404);
  const imposter = await t.parseSigner((await t.generateKey(origin)).skey);
  assert.equal((await post(`old 6\n\n${await t.signCheckpoint(leaves(lines), imposter)}`)).status, 403);
  assert.equal((await post('hello')).status, 400);
  assert.equal((await s.call(s.witness, 'GET', '/add-checkpoint')).status, 405);
  assert.equal((await s.call(s.witness, 'GET', '/elsewhere')).status, 404);
  // The registry entry whose key does not parse is not accepted, and is remembered as such.
  assert.deepEqual(s.witness.rejected.map((x) => x.origin), ['bad.example/log']);
});

test('requests that arrive together are answered one after another', async () => {
  const s = await setup();
  const post = s.post(s.witness);
  const lines = grow([], 3);
  assert.equal((await post(`old 0\n\n${await t.signCheckpoint(leaves(lines), s.signer)}`)).status, 200);
  // Two operators' processes race from size 3: to 5 and to 7. Exactly one is cosigned from 3;
  // the other is told the size the witness now holds.
  grow(lines, 4);
  const req = async (n) => `old 3\n${t.consistencyProof(leaves(lines), 3, n).map((h) => t.b64(h) + '\n').join('')}\n${await t.signCheckpoint(leaves(lines), s.signer, n)}`;
  const [a, b] = await Promise.all([post(await req(5)), post(await req(7))]);
  assert.deepEqual([a.status, b.status], [200, 409]);
  assert.equal(b.body, '5\n');
});

test('uses the key in WITNESS_KEY when one is set', async () => {
  const k = await t.generateKey('witness.example/own', t.SIG_COSIGNATURE);
  const s = await setup({ WITNESS_KEY: k.skey + '\n' });
  assert.equal((await (await s.call(s.witness, 'GET', '/witness.vkey')).text()).trim(), k.vkey);
  assert.equal(await s.store.get('key'), undefined);
  const wrong = await setup({ WITNESS_KEY: (await t.generateKey('witness.example/own')).skey });
  const r = await wrong.call(wrong.witness, 'GET', '/witness.vkey');
  assert.equal(r.status, 500);
  assert.match(await r.text(), /not a witness key/);
});

// ---- a log is a name and a key; what an auditor leaves ----


const SITE = 'https://witness.example';
const NOW = '2026-11-18T01:00:00Z';

async function site() {
  const store = new MemoryStore();
  const op = await t.generateKey(origin);
  const auditor = await passkey({ origin: SITE });
  const state = { registry: { witness: { name: 'witness.example' }, operators: [{ origin, checkpoint_key: op.vkey, auditors: [auditor.entry] }] } };
  const make = () => new Witness({ store, registry: state.registry, now: () => new Date(NOW) });
  const call = (w, method, path, body) => w.handle(new Request(SITE + path, { method, body }));
  const statement = (over = {}) =>
    JSON.stringify({ type: 'audit-statement/v1', origin, auditor: '内部監査室', at: NOW, covers: { anchors: 3, root: 'AAAA', through: '2026-11-18T00:50:00Z' }, checks: { records: 'ok', anchors: 'ok', cosignature: 'ok' }, findings: { overdue: 0, late: 1, unapproved: 0, plan_mismatch: 0, not_told: 0, no_key: 0 }, ...over });
  const leave = async (w, s, credential) => {
    const r = await call(w, 'POST', '/results', JSON.stringify({ statement: s, credential: credential ?? (await auditor.sign(challengeFor(s))) }));
    return { status: r.status, body: await r.json() };
  };
  const results = async (w, o = origin) => (await call(w, 'GET', `/results.json?o=${encodeURIComponent(o)}`)).json();
  return { store, op, auditor, state, make, call, statement, leave, results };
}

test('keeps a statement signed with a registered auditor\'s key, newest first', async () => {
  const s = await site();
  const w = s.make();
  const first = s.statement();
  const r = await s.leave(w, first);
  assert.equal(r.status, 201);
  assert.equal(r.body.result.statement, first);
  const second = s.statement({ note: '二回目', findings: { overdue: 2, late: 0, unapproved: 0, plan_mismatch: 0, not_told: 0, no_key: 0 } });
  assert.equal((await s.leave(w, second)).status, 201);
  const got = await s.results(s.make());
  assert.deepEqual(got.results.map((x) => x.statement), [second, first]);
  assert.equal(got.results[0].received_at, new Date(NOW).toISOString());
  assert.equal((await s.call(w, 'GET', `/results.json?o=${encodeURIComponent(origin)}`)).headers.get('access-control-allow-origin'), '*');
  assert.equal((await s.call(w, 'GET', '/results')).status, 405);
});

test('refuses what a registered auditor did not sign here, now, for a log it knows', async () => {
  const s = await site();
  const w = s.make();
  const good = s.statement();
  const refused = async (what, status, st, credential) => {
    const r = await s.leave(w, st, credential);
    assert.equal(r.status, status, `${what}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.ok, false);
  };
  await refused('a statement changed after signing', 403, good.replace('"late":1', '"late":0'), await s.auditor.sign(challengeFor(good)));
  const stranger = await passkey({ origin: SITE });
  await refused('a key the registry does not name', 403, good, await stranger.sign(challengeFor(good)));
  await refused('another key under a registered id', 403, good, { ...(await stranger.sign(challengeFor(good))), id: s.auditor.entry.id });
  const elsewhere = await passkey({ origin: 'https://evil.example' });
  await refused('a signature made at another site', 403, good, { ...(await s.auditor.sign(challengeFor(good), { at: 'https://evil.example' })) });
  await refused('a key bound to another site', 403, good, { ...(await elsewhere.sign(challengeFor(good))), id: s.auditor.entry.id });
  await refused('a log that is not registered', 404, s.statement({ origin: 'other.example/log' }));
  await refused('a statement from yesterday', 400, s.statement({ at: '2026-11-17T01:00:00Z' }));
  await refused('a statement from the future', 400, s.statement({ at: '2026-11-18T01:11:00Z' }));
  await refused('too large', 413, s.statement({ note: 'x'.repeat(400), pad: 'y'.repeat(4000) }));
  await refused('a long note', 400, s.statement({ note: 'あ'.repeat(501) }));
  await refused('a finding left out', 400, s.statement({ findings: { overdue: 0 } }));
  await refused('a check that is neither ok nor failed', 400, s.statement({ checks: { records: 'ok', anchors: 'ok', cosignature: 'maybe' } }));
  await refused('another kind of statement', 400, s.statement({ type: 'something-else' }));
  await refused('not JSON', 400, 'hello');
  await refused('no credential', 400, good, {});
  assert.deepEqual((await s.results(w)).results, []);
  assert.equal((await s.call(w, 'GET', '/results.json?o=nobody.example/log')).status, 404);
});

test('at most the newest 200 statements are kept for a log', async () => {
  const s = await site();
  const w = s.make();
  for (let i = 0; i < 203; i++) assert.equal((await s.leave(w, s.statement({ note: String(i) }))).status, 201);
  const got = (await s.results(w)).results;
  assert.equal(got.length, 200);
  assert.equal(JSON.parse(got[0].statement).note, '202');
  assert.equal(JSON.parse(got[199].statement).note, '3');
});

test('a log registered again under a new key starts from nothing, and what was kept for the old one is deleted', async () => {
  const s = await site();
  const w = s.make();
  const post = async (wit, body) => {
    const r = await s.call(wit, 'POST', '/add-checkpoint', body);
    return { status: r.status, body: await r.text() };
  };
  const lines = grow([], 5);
  assert.equal((await post(w, `old 0\n\n${await t.signCheckpoint(leaves(lines), await t.parseSigner(s.op.skey))}`)).status, 200);
  assert.equal((await s.leave(w, s.statement())).status, 201);
  assert.equal((await (await s.call(w, 'GET', '/status.json')).json()).logs[origin].size, 5);

  // The operator starts over: the same name, a new key, a new chain.
  const op2 = await t.generateKey(origin);
  s.state.registry = { operators: [{ origin, checkpoint_key: op2.vkey, auditors: [s.auditor.entry] }] };
  const w2 = s.make();
  assert.deepEqual((await (await s.call(w2, 'GET', '/status.json')).json()).logs, {});
  assert.deepEqual((await s.results(w2)).results, []);
  assert.deepEqual([...s.store.m.keys()].sort(), ['key']);
  const fresh = grow([], 2, 'thing.new');
  const signer2 = await t.parseSigner(op2.skey);
  assert.equal((await post(w2, `old 0\n\n${await t.signCheckpoint(leaves(fresh), signer2)}`)).status, 200);
  // The old key no longer signs for this name.
  assert.equal((await post(w2, `old 2\n\n${await t.signCheckpoint(leaves(lines), await t.parseSigner(s.op.skey))}`)).status, 403);
  assert.equal((await (await s.call(w2, 'GET', '/status.json')).json()).logs[origin].size, 2);

  // A log taken out of the registry: nothing of it is kept.
  assert.equal((await s.leave(w2, s.statement())).status, 201);
  s.state.registry = { operators: [] };
  const w3 = s.make();
  assert.equal((await s.call(w3, 'GET', `/results.json?o=${encodeURIComponent(origin)}`)).status, 404);
  assert.deepEqual([...s.store.m.keys()].sort(), ['key']);
});
