// The witness: it cosigns the checkpoints of the logs in its registry, after
// checking the operator's signature and that the log only grew since the
// last checkpoint it cosigned (c2sp.org/tlog-witness, add-checkpoint). It
// also keeps what the operators' own auditors leave here: statements of what
// they verified, each signed with a passkey the registry names.
//
// It keeps, per log, the last checkpoint it cosigned and the auditors'
// statements, and its own key. It never holds an operator's records: what it
// cosigns is a chain of one commitment per interval. `store` is the storage
// of a Durable Object, or anything with the same `get` / `put` / `delete` /
// `list({ prefix })`.
import { SIG_COSIGNATURE, addCheckpoint, b64, generateKey, parseSigner, parseVerifier, unb64 } from '../public/deedlog.js';
import { challengeFor, verifyAssertion } from '../public/webauthn.js';

const CORS = { 'access-control-allow-origin': '*' };
const text = (body, status = 200, headers = {}) => new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body, null, 1) + '\n', { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });

const FINDINGS = ['overdue', 'late', 'unapproved', 'plan_mismatch', 'not_told', 'no_key'];
const CHECKS = ['records', 'anchors', 'cosignature'];
const MAX_STATEMENT = 4096;
const KEEP = 200;
const SKEW = 10 * 60_000;

class Refused extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** Reads an auditor's statement and refuses anything that is not one. */
export function parseStatement(statement) {
  if (typeof statement !== 'string' || !statement) throw new Refused(400, 'statement: the statement as a JSON string');
  if (new TextEncoder().encode(statement).length > MAX_STATEMENT) throw new Refused(413, `statement: at most ${MAX_STATEMENT} bytes`);
  let s;
  try {
    s = JSON.parse(statement);
  } catch {
    throw new Refused(400, 'statement: not JSON');
  }
  const bad = (what) => {
    throw new Refused(400, `statement: ${what}`);
  };
  if (!s || typeof s !== 'object' || Array.isArray(s)) bad('not an object');
  if (s.type !== 'audit-statement/v1') bad('type must be audit-statement/v1');
  if (typeof s.origin !== 'string' || !s.origin) bad('origin is missing');
  if (typeof s.auditor !== 'string' || !s.auditor || s.auditor.length > 80) bad('auditor: a name of at most 80 characters');
  if (typeof s.at !== 'string' || Number.isNaN(Date.parse(s.at))) bad('at: a time');
  const c = s.covers;
  if (!c || typeof c !== 'object' || !Number.isInteger(c.anchors) || c.anchors < 0 || typeof c.root !== 'string' || typeof c.through !== 'string') bad('covers: { anchors, root, through }');
  if (!s.checks || typeof s.checks !== 'object' || !CHECKS.every((k) => s.checks[k] === 'ok' || s.checks[k] === 'failed')) bad(`checks: ${CHECKS.join(', ')}, each ok or failed`);
  if (!s.findings || typeof s.findings !== 'object' || !FINDINGS.every((k) => Number.isInteger(s.findings[k]) && s.findings[k] >= 0)) bad(`findings: a count for each of ${FINDINGS.join(', ')}`);
  if (s.note !== undefined && (typeof s.note !== 'string' || s.note.length > 500)) bad('note: at most 500 characters');
  return s;
}

export class Witness {
  /**
   * @param {{ store: any, env?: { WITNESS_KEY?: string, WITNESS_NAME?: string, SITE_ORIGIN?: string }, now?: () => Date, registry: { operators?: { origin: string, checkpoint_key: string, auditors?: { name: string, id: string, key: string, alg?: number }[] }[] } }} opts
   */
  constructor({ store, env = {}, now = () => new Date(), registry }) {
    this.witnessName = registry?.witness?.name;
    this.store = store;
    this.env = env;
    this.now = now;
    // What the witness accepts: for each origin, the operator's verifier key and its auditors.
    this.logs = new Map();
    this.rejected = [];
    for (const op of registry?.operators ?? []) {
      try {
        const v = parseVerifier(op.checkpoint_key);
        if (v.name !== op.origin) throw new Error(`the key is for ${v.name}`);
        const auditors = (op.auditors ?? []).filter((a) => a && typeof a.id === 'string' && typeof a.key === 'string' && (a.alg === undefined || a.alg === -7));
        this.logs.set(op.origin, { verifier: v, auditors });
      } catch (e) {
        this.rejected.push({ origin: String(op.origin), reason: e.message });
      }
    }
    this.lock = Promise.resolve();
  }

  /** The witness's name, in its key and its cosignature lines: WITNESS_NAME, or the registry's. */
  name() {
    const name = this.env.WITNESS_NAME || this.witnessName;
    if (!name) throw new Error('the witness has no name: set WITNESS_NAME in wrangler.jsonc (its host name, e.g. witness.example.org)');
    return name;
  }

  /** The witness's key: the secret if one is set, or else one made on first use and kept in the store. */
  signer() {
    this.signing ??= (async () => {
      let skey = this.env.WITNESS_KEY?.trim();
      if (!skey) {
        skey = await this.store.get('key');
        if (!skey) {
          skey = (await generateKey(this.name(), SIG_COSIGNATURE)).skey;
          await this.store.put('key', skey);
        }
      }
      const signer = await parseSigner(skey);
      if (signer.typ !== SIG_COSIGNATURE) throw new Error('WITNESS_KEY is not a witness key (create one with dlog keygen -witness)');
      return signer;
    })();
    // A failure is not kept: the next request tries again.
    this.signing.catch(() => (this.signing = undefined));
    return this.signing;
  }

  /** Runs `fn` after every call before it has finished: check-and-update is one step. */
  serialized(fn) {
    const run = this.lock.then(fn, fn);
    this.lock = run.catch(() => undefined);
    return run;
  }

  // A log is a name and a key: the same name registered under a new key is a
  // new log, and starts from nothing. What is kept is kept under both.
  suffix(origin) {
    const log = this.logs.get(origin);
    return log && `${log.verifier.id}:${origin}`;
  }

  /** Once per start: what is kept for a log that is no longer in the registry is deleted. */
  ready() {
    this.cleaning ??= this.serialized(async () => {
      const keep = new Set([...this.logs.keys()].map((o) => this.suffix(o)));
      for (const prefix of ['log:', 'results:']) {
        for (const k of (await this.store.list({ prefix })).keys()) if (!keep.has(k.slice(prefix.length))) await this.store.delete(k);
      }
    });
    this.cleaning.catch(() => (this.cleaning = undefined));
    return this.cleaning;
  }

  async latest(origin) {
    const c = await this.store.get(`log:${this.suffix(origin)}`);
    return c ? { size: c.size, root: unb64(c.root), time: c.time } : undefined;
  }

  async status() {
    const logs = {};
    for (const origin of this.logs.keys()) {
      const c = await this.store.get(`log:${this.suffix(origin)}`);
      if (c) logs[origin] = c;
    }
    return { witness: (await this.signer()).vkey, logs };
  }

  /** Where this site is: what a passkey's signature made here names. */
  site(request) {
    return new URL(this.env.SITE_ORIGIN || request.url).origin;
  }

  /** Takes an auditor's signed statement, if the registry names the key that signed it. */
  async addResult(request) {
    const raw = await request.text();
    if (raw.length > 4 * MAX_STATEMENT) throw new Refused(413, 'request too large');
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      throw new Refused(400, 'the request is not JSON');
    }
    const s = parseStatement(body?.statement);
    const log = this.logs.get(s.origin);
    if (!log) throw new Refused(404, 'unknown origin');
    const c = body.credential;
    if (!c || !['id', 'authenticatorData', 'clientDataJSON', 'signature'].every((k) => typeof c[k] === 'string' && c[k].length <= 4096)) throw new Refused(400, 'credential: { id, authenticatorData, clientDataJSON, signature }');
    const auditor = log.auditors.find((a) => a.id === c.id);
    if (!auditor) throw new Refused(403, 'this key is not registered as an auditor of that log');
    if (Math.abs(Date.parse(s.at) - this.now().getTime()) > SKEW) throw new Refused(400, 'statement: its time is more than ten minutes from now');
    const origin = this.site(request);
    try {
      await verifyAssertion({ key: auditor.key, credential: c, challenge: challengeFor(body.statement), origin, rpId: new URL(origin).hostname });
    } catch (e) {
      throw new Refused(403, `the signature was not accepted: ${e.message}`);
    }
    const entry = { statement: body.statement, credential: { id: c.id, authenticatorData: c.authenticatorData, clientDataJSON: c.clientDataJSON, signature: c.signature }, received_at: this.now().toISOString() };
    await this.serialized(async () => {
      const key = `results:${this.suffix(s.origin)}`;
      const kept = (await this.store.get(key)) ?? [];
      await this.store.put(key, [entry, ...kept].slice(0, KEEP));
    });
    return entry;
  }

  /** @param {Request} request */
  async handle(request) {
    const url = new URL(request.url);
    const { pathname } = url;
    try {
      await this.ready();
      if (pathname === '/add-checkpoint') {
        if (request.method !== 'POST') return text('POST a checkpoint here\n', 405, { allow: 'POST' });
        const body = await request.text();
        if (body.length > 1 << 20) return text('request too large\n', 413);
        const signer = await this.signer();
        const r = await this.serialized(() =>
          addCheckpoint(body, {
            signer,
            logs: (origin) => this.logs.get(origin)?.verifier,
            latest: (origin) => this.latest(origin),
            put: (origin, c) => this.store.put(`log:${this.suffix(origin)}`, { size: c.size, root: b64(c.root), time: c.time }),
            now: this.now,
          }),
        );
        return text(r.body, r.status, r.type ? { 'content-type': r.type } : {});
      }
      if (pathname === '/results') {
        if (request.method !== 'POST') return text('POST a signed statement here\n', 405, { allow: 'POST' });
        try {
          return json({ ok: true, result: await this.addResult(request) }, 201);
        } catch (e) {
          if (e instanceof Refused) return json({ ok: false, error: e.message }, e.status);
          throw e;
        }
      }
      if (request.method !== 'GET' && request.method !== 'HEAD') return text('not found\n', 404);
      if (pathname === '/witness.vkey') return text((await this.signer()).vkey + '\n', 200, CORS);
      if (pathname === '/status.json') return json(await this.status(), 200, CORS);
      if (pathname === '/results.json') {
        const origin = url.searchParams.get('o') ?? '';
        if (!this.logs.has(origin)) return json({ origin, results: [], error: 'unknown origin' }, 404, CORS);
        return json({ origin, results: (await this.store.get(`results:${this.suffix(origin)}`)) ?? [] }, 200, CORS);
      }
      return text('not found\n', 404);
    } catch (e) {
      return text(`the witness is not set up: ${e.message}\n`, 500);
    }
  }
}
