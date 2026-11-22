// A local stand-in for the whole setting: this site's files, the witness, and
// a few operators in different states, for the page tests and for looking at
// the page by hand (`node test/fixture.mjs`).
//
// An operator here does what a real one does: it keeps its records to
// itself, appends one commitment per interval to a public chain, has that
// chain cosigned, hands a person their own records with proofs, and hands
// its auditor everything after a passkey signature.
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as t from '../public/deedlog.js';
import { challengeFor, verifyAssertion } from '../public/webauthn.js';
import { Witness } from '../src/witness.js';
import { passkey } from './passkey.mjs';
import { MemoryStore } from './store.mjs';

const PUBLIC = fileURLToPath(new URL('../public/', import.meta.url));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png' };
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const INTERVAL = 10 * MIN;

export const itemOf = (token) => t.sha256hex(token).slice(0, 32);
const dutyId = (rule, item) => t.sha256hex([rule, `item=${item}`].join('\x1f')).slice(0, 12);
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const hex16 = () => randomBytes(16).toString('hex');

const RULES = [
  { rule: 'handle-inquiry', title: 'お問い合わせには3日以内に対応する', source: 'お問い合わせ対応規程 第4条', when: 'data.received', expect: 'data.answered', within: '3d', approval: 'none' },
  { rule: 'purge-plaintext', title: '復号した内容の写しは24時間以内に端末から消す', source: '個人情報取扱規程 第9条', when: 'data.decrypted', expect: 'data.plaintext_purged', within: '24h', approval: 'none' },
  { rule: 'delete-after-answer', title: '対応が済んだお問い合わせは30日以内に削除する', source: '個人情報取扱規程 第12条', when: 'data.answered', expect: 'data.deleted', within: '30d', approval: 'required' },
];

const lifecycle = (item, start, upTo) =>
  [
    [start, 'data.received', { item, form: 'contact', by: 'site' }],
    [start - 2 * MIN, 'duty.alerted', { duty: dutyId('handle-inquiry', item), stage: 'due', to: 'support', item, via: 'support-agent' }],
    [start - 3 * MIN, 'data.decrypted', { item, form: 'contact', by: 'support-agent' }],
    [start - 9 * MIN, 'data.answered', { item, form: 'contact', by: 'support', outcome: 'replied' }],
    [start - 10 * MIN, 'data.plaintext_purged', { item, form: 'contact', by: 'support-agent' }],
    [start - 11 * MIN, 'duty.approval_requested', { duty: dutyId('delete-after-answer', item), item, plan: t.sha256hex('plan' + item), by: 'support-agent' }],
    [start - 13 * MIN, 'duty.approved', { duty: dutyId('delete-after-answer', item), item, by: 'manager', plan: t.sha256hex('plan' + item), channel: 'cucon-screen' }],
    [start - 14 * MIN, 'data.deleted', { item, form: 'contact', by: 'support-agent', plan: t.sha256hex('plan' + item), place: 'google-form:contact', rows: '1', responses: '1', verified: 'absent' }],
  ].slice(0, upTo);

/** One operator: its private chain, the public chain of commitments, and what it answers. */
class Operator {
  constructor({ id, name, now }) {
    this.id = id;
    this.name = name;
    this.now = now;
    this.origin = `${id}.example/dlm`;
    this.chain = `${this.origin}/records`;
    this.lines = [];
    this.bodies = [];
    this.outer = [];
    this.anchors = [];
    this.auditors = [];
    this.challenges = new Set();
    this.checkpoint = '';
    this.tamper = {};
  }

  async init() {
    this.key = await t.generateKey(this.origin);
    this.signer = await t.parseSigner(this.key.skey);
    return this;
  }

  add(ago, event, meta) {
    const { line, body } = t.makeRecord(t.readChain(this.lines), { name: this.chain, source: { type: 'cucon', id: this.chain, collector: 'test' }, event, meta, at: new Date(this.now - ago) });
    this.lines.push(line);
    this.bodies.push(body);
  }

  /** Commits to everything added since the last time, under the interval that ended `ago` before now. */
  anchor(ago) {
    const from = this.anchors.at(-1)?.to ?? 0;
    const to = this.lines.length;
    const epoch = iso(Math.floor((this.now - ago) / INTERVAL) * INTERVAL);
    const secrets = { nonce: hex16(), pad: hex16() };
    const a = t.anchor(this.lines.slice(from, to), { chain: this.chain, epoch, ...secrets });
    const seq = this.outer.length;
    this.outer.push(t.nextRecord(t.readChain(this.outer), { name: this.origin, source: { type: 'cucon', id: this.origin, collector: 'test' }, event: 'chain.anchored', meta: { epoch, commit: a.commit }, at: new Date(this.now - ago) }));
    this.anchors.push({ seq, epoch, from, to, size: a.size, ...secrets });
  }

  /** Signs the public chain as it is and, unless told not to, has the witness cosign it. */
  async publish(post, witnessKey, held) {
    const leaves = this.outer.map((l) => t.leafHash(l));
    let note = await t.signCheckpoint(leaves, this.signer);
    if (post) note += (await t.requestCosignature(note, leaves, witnessKey, post, held ?? 0)).lines.join('');
    this.checkpoint = note;
  }

  /** What is handed out for record `i`: where it sits in its interval, never its line. */
  proofFor(i) {
    const a = this.anchors.find((x) => i >= x.from && i < x.to);
    return a && t.recordProof(this.lines.slice(a.from, a.to), i - a.from, a);
  }

  bundle(pick) {
    const records = [];
    this.bodies.forEach((body, i) => {
      const about = JSON.parse(body);
      if (!pick(about)) return;
      const anchor = this.proofFor(i);
      records.push({ body: this.tamper.item?.(body, about) ?? body, ...(anchor ? { anchor } : {}) });
    });
    return { origin: this.origin, chain: this.chain, records };
  }

  everything() {
    return { origin: this.origin, chain: this.chain, records: this.lines, anchors: this.anchors };
  }
}

export async function startFixture({ port = 0, now = Date.now() } = {}) {
  const tokens = { full: 'Zk3vT0q9mB1xYw7cR2dLhA', due: 'pQ8sN5uJ4eG6tV1bX0zKfM', overdue: 'aH2jD7lO9rC3yI6wU8nEsB', fresh: 'mW4xK9pZ2sQ7vB1nT6cJyR', unknown: 'nobody-has-this-token0' };
  const ops = {};
  const make = async (id, name, build) => {
    const op = await new Operator({ id, name, now }).init();
    for (const r of RULES) op.add(40 * DAY, 'rule.adopted', { ...r, notice: r.within, owner: 'support', escalate: 'manager', per: 'item', by: 'manager', digest: t.sha256hex(r.rule) });
    op.add(40 * DAY - MIN, 'key.published', { form: 'contact', by: 'support' });
    op.anchor(40 * DAY - 10 * MIN);
    build(op);
    ops[id] = op;
    return op;
  };

  // Everything anchored, over several intervals; some of them empty.
  await make('full', '合同会社Burug お問い合わせの取り扱い記録', (op) => {
    const steps = lifecycle(itemOf(tokens.full), 60 * MIN);
    for (const s of steps.slice(0, 3)) op.add(...s);
    op.anchor(55 * MIN);
    for (const s of steps.slice(3, 7)) op.add(...s);
    op.add(46 * MIN, 'data.received', { item: itemOf('another'), form: 'contact', by: 'site' });
    op.anchor(45 * MIN);
    op.add(38 * MIN, 'data.deleted', steps[7][2]);
    op.anchor(35 * MIN);
    // Nothing happened in these intervals; a commitment is deposited all the same.
    op.anchor(25 * MIN);
    op.anchor(15 * MIN);
    op.anchor(5 * MIN);
  });
  // Deadlines: one inquiry with its deletion still due, one long overdue.
  await make('due', '例示株式会社 お問い合わせの取り扱い記録', (op) => {
    op.add(3 * DAY + 60 * MIN, 'data.received', { item: itemOf(tokens.overdue), form: 'contact', by: 'site' });
    op.add(30 * 60 * MIN, 'data.decrypted', { item: itemOf(tokens.overdue), form: 'contact', by: 'support-agent' });
    for (const s of lifecycle(itemOf(tokens.due), 50 * MIN, 5)) op.add(s[0], s[1], s[1] === 'data.answered' ? { ...s[2], outcome: 'no_reply_needed' } : s[2]);
    op.anchor(0);
  });
  // The last interval has not come yet: some records wait, and one inquiry has nothing confirmed.
  await make('waiting', '確認待ちのある記録', (op) => {
    for (const s of lifecycle(itemOf(tokens.full), 25 * MIN, 3)) op.add(...s);
    op.anchor(20 * MIN);
    for (const s of lifecycle(itemOf(tokens.full), 25 * MIN, 5).slice(3)) op.add(...s);
    op.add(2 * MIN, 'data.received', { item: itemOf(tokens.fresh), form: 'contact', by: 'site' });
  });
  // What is handed over about a record is not what was committed to.
  await make('altered', '書き換えられた記録', (op) => {
    for (const s of lifecycle(itemOf(tokens.full), 30 * MIN)) op.add(...s);
    op.anchor(0);
    op.tamper.item = (body, about) => (about.event === 'data.decrypted' ? body.replace('"by":"support-agent"', '"by":"support"') : undefined);
  });
  // The public chain itself was changed after it was signed.
  await make('tampered', '要約が書き換えられた記録', (op) => {
    for (const s of lifecycle(itemOf(tokens.full), 30 * MIN)) op.add(...s);
    op.anchor(10 * MIN);
    op.anchor(0);
    op.tamper.outer = true;
  });
  await make('nocosig', '連署のない記録', (op) => {
    for (const s of lifecycle(itemOf(tokens.full), 30 * MIN)) op.add(...s);
    op.anchor(0);
    op.tamper.nocosig = true;
  });

  const server = createServer((req, res) => handle(req, res).catch((e) => res.writeHead(500).end(String(e?.stack ?? e))));
  await new Promise((r) => server.listen(port, 'localhost', r));
  const base = `http://localhost:${server.address().port}`;

  // The witness and its registry. An auditor registered later is a new start of the witness over the same store.
  const store = new MemoryStore();
  const registry = () => ({
    witness: { name: 'witness.euca.in', operator: '一般社団法人エンドユーザーコンピューティング協会', short_name: 'EUCA' },
    quorum: 1,
    operators: Object.values(ops).map((op) => ({ name: op.name, origin: op.origin, checkpoint_key: op.key.vkey, url: `/logs/${op.id}`, auditors: op.auditors, ...(op.direct ? { kind: 'direct', site: op.site } : {}) })),
  });
  let witness = new Witness({ store, registry: registry(), now: () => new Date(now) });
  const witnessKey = t.parseVerifier((await (await witness.handle(new Request(`${base}/witness.vkey`))).text()).trim());
  const post = async (body) => {
    const r = await witness.handle(new Request(`${base}/add-checkpoint`, { method: 'POST', body }));
    return { status: r.status, body: await r.text() };
  };
  for (const op of Object.values(ops)) {
    await op.publish(op.tamper.nocosig ? undefined : post, witnessKey);
    if (op.tamper.outer) op.outer[1] = op.outer[1].replace(/"commit":"(.)/, (_, c) => `"commit":"${c === '0' ? '1' : '0'}`);
  }

  /** Registers an auditor's key: with the operator, and in the witness's registry. */
  function addAuditor(id, entry) {
    ops[id].auditors.push(entry);
    witness = new Witness({ store, registry: registry(), now: () => new Date(now) });
  }

  // What the auditor of `full` left here earlier: one statement that verifies, and one that was changed afterwards.
  const auditor = await passkey({ origin: base, name: '内部監査室' });
  addAuditor('full', auditor.entry);
  const statement = (at, findings, note) =>
    JSON.stringify({ type: 'audit-statement/v1', origin: ops.full.origin, auditor: '内部監査室', at: iso(at), covers: { anchors: ops.full.outer.length, root: t.b64(t.merkleRoot(ops.full.outer.map((l) => t.leafHash(l)))), through: ops.full.anchors.at(-1).epoch }, checks: { records: 'ok', anchors: 'ok', cosignature: 'ok' }, findings: { overdue: 0, late: 0, unapproved: 0, plan_mismatch: 0, not_told: 0, no_key: 0, ...findings }, ...(note ? { note } : {}) });
  const leave = async (s) => {
    const r = await witness.handle(new Request(`${base}/results`, { method: 'POST', body: JSON.stringify({ statement: s, credential: await auditor.sign(challengeFor(s)) }) }));
    if (r.status !== 201) throw new Error(`fixture result refused: ${await r.text()}`);
  };
  await leave(statement(now - 5 * MIN, { late: 1 }, '10月分を確認しました。期限後の完了が1件ありましたが、担当者に理由を確認済みです。'));
  await leave(statement(now - 2 * MIN, {}));
  {
    // Changed after it was signed: it still sits in the store, and must be shown as not verifying.
    const key = [...store.m.keys()].find((k) => k.startsWith('results:') && k.endsWith(ops.full.origin));
    const kept = store.m.get(key);
    kept[0] = { ...kept[0], statement: kept[0].statement.replace('"overdue":0', '"overdue":7') };
  }

  // A log of the other kind: the records themselves are public, because what they are about is.
  const direct = {};
  for (const [id, name, tamper] of [['ledger', '公開している帳簿の更新の記録'], ['rewritten', '書き換えられた帳簿の記録', true]]) {
    const op = await new Operator({ id, name, now }).init();
    op.direct = true;
    op.site = `${base}/ledger-site/${id}`;
    const at = (ago, event, meta) => op.outer.push(t.nextRecord(t.readChain(op.outer), { name: op.origin, source: { type: 'ledger', id: 'admin', collector: 'test' }, event, meta, at: new Date(now - ago) }));
    at(3 * DAY, 'ledger.opened', {});
    for (let i = 1; i <= 12; i++) at(3 * DAY - i * MIN, 'transaction.created', { org: 'sample', year: '2026', no: String(7000 + i) });
    at(DAY, 'transaction.updated', { org: 'sample', year: '2026', no: '7002', replaces: t.sha256hex('before') });
    at(DAY - MIN, 'transaction.deleted', { org: 'sample', year: '2026', no: '7012' });
    ops[id] = op;
    // The witness learns of a new log when it starts again with the registry that names it.
    witness = new Witness({ store, registry: registry(), now: () => new Date(now) });
    await op.publish(post, witnessKey);
    // One more, not cosigned yet.
    at(10 * MIN, 'transaction.created', { org: 'sample', year: '2026', no: '7013' });
    if (tamper) op.outer[13] = op.outer[13].replace('"no":"7002"', '"no":"7003"');
    direct[id] = op;
  }

  async function handle(req, res) {
    const url = new URL(req.url, base);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    const send = (status, type, out) => res.writeHead(status, { 'content-type': type, 'access-control-allow-origin': '*', 'cache-control': 'no-store' }).end(out);
    const sendJson = (status, out) => send(status, 'application/json', JSON.stringify(out));

    const m = /^\/logs\/([a-z]+)\/(.+)$/.exec(url.pathname);
    if (m && ops[m[1]]) {
      const op = ops[m[1]];
      if (m[2] === 'checkpoint') return send(200, 'text/plain; charset=utf-8', op.checkpoint);
      if (m[2] === 'chain.jsonl') return send(200, 'text/plain; charset=utf-8', op.outer.join('\n') + '\n');
      if (m[2] === 'key') return send(200, 'text/plain; charset=utf-8', op.key.vkey + '\n');
      if (m[2] === 'item') return sendJson(200, op.bundle((meta) => meta.item === url.searchParams.get('ref')));
      if (m[2] === 'rules') return sendJson(200, op.bundle((meta) => meta.event === 'rule.adopted' || meta.event === 'rule.retired'));
      if (m[2] === 'audit/challenge' && req.method === 'POST') {
        const challenge = t.b64url(randomBytes(32));
        op.challenges.add(challenge);
        return sendJson(200, { challenge });
      }
      if (m[2] === 'audit/chain' && req.method === 'POST') {
        const credential = JSON.parse(body || '{}').credential ?? {};
        const who = op.auditors.find((a) => a.id === credential.id);
        if (!who) return sendJson(403, { ok: false, error: 'この鍵は登録されていません' });
        let challenge;
        try {
          challenge = JSON.parse(Buffer.from(credential.clientDataJSON, 'base64url').toString()).challenge;
          if (!op.challenges.delete(challenge)) throw new Error('the challenge is not one this operator gave');
          await verifyAssertion({ key: who.key, credential, challenge, origin: base, rpId: 'localhost' });
        } catch (e) {
          return sendJson(403, { ok: false, error: e.message });
        }
        op.add(0, 'audit.viewed', { by: 'audit' });
        return sendJson(200, op.everything());
      }
      return send(404, 'text/plain', 'not found\n');
    }
    if (url.pathname === '/test-registry.json') return sendJson(200, registry());
    if (['/witness.vkey', '/status.json', '/results', '/results.json'].includes(url.pathname)) {
      const r = await witness.handle(new Request(url, { method: req.method, ...(req.method === 'POST' ? { body } : {}) }));
      return send(r.status, r.headers.get('content-type'), await r.text());
    }
    try {
      const path = normalize(join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname));
      if (!path.startsWith(PUBLIC)) throw new Error('outside');
      send(200, TYPES[extname(path)] ?? 'application/octet-stream', await readFile(path));
    } catch {
      send(404, 'text/plain', 'not found\n');
    }
  }

  const link = (id, token, extra = '') => `${base}/?registry=/test-registry.json#o=${id}.example/dlm${token ? `&t=${token}` : ''}${extra}`;
  return { base, tokens, ops, link, addAuditor, list: `${base}/?registry=/test-registry.json`, close: () => new Promise((r) => server.close(r)) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const f = await startFixture({ port: Number(process.env.PORT ?? 8930) });
  console.log(f.list);
  for (const [id, token, extra] of [['full', f.tokens.full], ['due', f.tokens.due], ['due', f.tokens.overdue], ['waiting', f.tokens.full], ['waiting', f.tokens.fresh], ['full', f.tokens.unknown], ['altered', f.tokens.full], ['tampered', f.tokens.full], ['nocosig', f.tokens.full], ['full'], ['full', '', '&audit']]) console.log(f.link(id, token, extra));
}
