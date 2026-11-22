// The verification page. Everything is checked here, in the reader's
// browser: the page fetches the registry, the operator's public chain of
// commitments and its checkpoint, and trusts none of them until the
// signatures and the hashes agree. Records stay with the operator: a person
// is handed what their own records say, each with a proof that it was
// committed to, and nothing that tells where a record sits in the operator's
// chain; the operator's auditor is handed all of it after signing in with a
// passkey.
// The token in a person's link stays in the fragment; only a value computed
// from it is sent, to the operator, to ask for that person's records.
import { anchor as anchorOf, b64, b64url, commitOf, equal, hex, leafHash, merkleRoot, parseVerifier, readChain, sha256, unb64, utf8, verifyCheckpoint } from './deedlog.js';
import { challengeFor, unb64url, verifyAssertion } from './webauthn.js';

const app = document.getElementById('app');
// Who runs this witness, as the registry's "witness" says: shown wherever the page speaks of the witness.
let WN = '連署サーバーの運営者';
const LOCAL = ['localhost', '127.0.0.1'].includes(location.hostname);

// ---- small helpers ----

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === false || v === undefined || v === null) continue;
    if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === false || c === undefined || c === null) continue;
    el.append(c.nodeType ? c : String(c));
  }
  return el;
}

const jst = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
function when(t, seconds = true) {
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return '日時不明';
  const p = Object.fromEntries(jst.formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.year}年${p.month}月${p.day}日 ${p.hour === '24' ? '00' : p.hour}:${p.minute}${seconds ? ':' + p.second : ''}`;
}

async function get(url) {
  const res = await fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.text();
}
const getJson = (url) => get(url).then(JSON.parse);
async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}), cache: 'no-store', signal: AbortSignal.timeout(20000) });
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(out.error || `${res.status}`);
  return out;
}

const WHO = { 'support-agent': '対応担当のAIエージェント', support: '対応担当', manager: '情報管理責任者', site: 'フォーム', audit: '内部監査室' };
const who = (id) => WHO[id] ?? id;

const duration = (s) => {
  const m = /^(\d{1,5})([dhm])$/.exec(s ?? '');
  return m ? Number(m[1]) * { d: 86_400_000, h: 3_600_000, m: 60_000 }[m[2]] : undefined;
};
const span = (s) => {
  const m = /^(\d{1,5})([dhm])$/.exec(s ?? '');
  return m ? `${m[1]}${{ d: '日', h: '時間', m: '分' }[m[2]]}` : s;
};

// ---- the rules a chain holds, and what they ask for one item ----

function rulesOf(entries) {
  const versions = new Map();
  for (const e of entries) {
    const id = e.meta.rule;
    if (!id) continue;
    if (e.event === 'rule.adopted') {
      const where = Object.entries(e.meta).filter(([k]) => k.startsWith('where.')).map(([k, v]) => [k.slice(6), v]);
      versions.set(id, [...(versions.get(id) ?? []), { id, title: e.meta.title ?? id, source: e.meta.source, when: e.meta.when, expect: e.meta.expect, within: e.meta.within, approval: e.meta.approval, per: e.meta.per ?? 'item', where, at: e.at, state: e.state, retired: false }]);
    } else if (e.event === 'rule.retired') {
      const last = versions.get(id)?.at(-1);
      if (last) last.retired = true;
    }
  }
  return [...versions.values()].map((v) => ({ ...v.at(-1), firstAt: v[0].at })).filter((r) => !r.retired);
}

/** The same id an operator's service gives a duty: the rule and the thing it is about. */
const dutyId = (rule, item) => hex(sha256(utf8([rule, `item=${item}`].join(String.fromCharCode(0x1f))))).slice(0, 12);

/** What the rules ask for one item, from that item's records in the order they were made. */
function plansFor(rules, mine, now) {
  const out = [];
  for (const rule of rules) {
    if (rule.per !== 'item') continue;
    const ms = duration(rule.within);
    if (ms === undefined) continue;
    const i = mine.findIndex((e) => e.event === rule.when && rule.where.every(([k, v]) => e.meta[k] === v));
    if (i < 0) continue;
    const trigger = mine[i];
    const done = mine.slice(i + 1).find((e) => e.event === rule.expect);
    // What was already there when the rule was first adopted comes under it from the adoption on.
    const due = Math.max(Date.parse(rule.firstAt), Date.parse(trigger.at)) + ms;
    out.push({ rule, due, done, late: done ? Date.parse(done.at) > due : now > due });
  }
  return out;
}

// ---- words for events ----

function describe(e, rules) {
  switch (e.event) {
    case 'data.received':
      return { step: '受付', title: 'お問い合わせを受け付けました', note: '入力された内容は、送信の前にお使いのブラウザで暗号化されています。', by: e.meta.by ?? 'site' };
    case 'data.decrypted':
      return { step: '復号', title: '担当者が内容を読むために復号しました' };
    case 'data.plaintext_purged':
      return { step: '写しの削除', title: '担当者の端末から、復号した内容の写しを削除しました' };
    case 'data.answered':
      return { step: '対応完了', title: e.meta.outcome === 'no_reply_needed' ? '対応が完了しました（返信不要と判断しました）' : e.meta.outcome === 'replied' ? '対応が完了しました（返信しました）' : '対応が完了しました' };
    case 'data.deleted':
      return { step: '削除', title: 'お預かりした情報（暗号文）を削除しました', final: true };
    case 'duty.approval_requested':
      return { step: '承認の依頼', title: `${approvalOf(e, rules)}の承認を依頼しました`, minor: true };
    case 'duty.approved':
      return { step: '承認', title: `${approvalOf(e, rules)}を承認しました` };
    case 'duty.approval_rejected':
      return { step: '承認', title: `${approvalOf(e, rules)}の承認を見送りました` };
    case 'duty.alerted':
      return { step: '通知', title: e.meta.stage === 'overdue' ? '期限を過ぎた作業があることを知らせました' : '期限のある作業を担当者に知らせました', minor: true, by: e.meta.by ?? e.meta.via };
    default:
      return { step: 'その他', title: e.event, minor: true };
  }
}

function approvalOf(e, rules) {
  const rule = rules.find((r) => e.meta.item && dutyId(r.id, e.meta.item) === e.meta.duty);
  if (!rule) return '作業';
  return rule.expect === 'data.deleted' ? '削除' : `「${rule.title}」の実行`;
}

const PROBLEMS = [
  [/^not JSON/, '要約として読めません。'],
  [/^prev does not match/, 'ひとつ前の要約とつながりません。要約が変更、削除、または並べ替えられています。'],
  [/^the first record names/, '先頭より前にあったはずの要約がありません。'],
  [/^seq is/, '通し番号が合いません。'],
  [/^spec is/, '形式が違います。'],
  [/^chain is/, '別の記録簿の要約が混ざっています。'],
  [/^not a commitment/, '区間の要約ではないものが混ざっています。'],
];
const problemText = (p, noun = '要約') => `${p.line} 件目の${noun}: ${(PROBLEMS.find(([re]) => re.test(p.reason))?.[1] ?? p.reason).replaceAll('要約', noun)}`;

// ---- checking what the operator publishes ----

/**
 * A log is one of two kinds (`kind` in the registry). `anchored`, the
 * default: the operator keeps its records and publishes one commitment per
 * interval, so that nothing tells how much it did or when. `direct`: the
 * operator publishes the records themselves, because what they are about is
 * public already (a published ledger, say), and checking them one by one
 * against it is the point.
 */
const isDirect = (op) => op.kind === 'direct';

async function verifyAnchors(op, witnessKey, status) {
  const direct = isDirect(op);
  const noun = direct ? '記録' : '要約';
  const r = { op, direct, noun, checks: [], verdict: 'ok', reasons: [], entries: [], lines: [], size: 0 };
  const check = (label, state, detail) => r.checks.push({ label, state, detail });
  const fail = (reason) => {
    r.verdict = 'fail';
    r.reasons.push(reason);
  };

  let operator;
  let witness;
  try {
    operator = parseVerifier(op.checkpoint_key);
    witness = parseVerifier(witnessKey);
  } catch (e) {
    r.verdict = 'unavailable';
    r.reasons.push(`登録簿にある検証用の鍵を読めません（${e.message}）。`);
    return r;
  }

  let note;
  let lines;
  r.base = op.url.replace(/\/$/, '');
  try {
    lines = (await get(`${r.base}/chain.jsonl`)).split('\n').filter(Boolean);
    // A log that has only just begun has deposited nothing yet: that is waiting, not failing.
    if (!lines.length) {
      r.verdict = 'pending';
      check('第三者の連署', 'warn', direct ? 'この記録簿には、まだ記録がありません。' : 'この記録は始まったばかりで、最初の区間の要約がまだ預けられていません。最初の区間が終わると預けられます。');
      return r;
    }
    note = await get(`${r.base}/checkpoint`);
  } catch {
    r.verdict = 'unavailable';
    r.reasons.push('運用者のサーバーから情報を取得できませんでした。時間をおいて、もう一度開いてください。');
    return r;
  }

  // 1. The chain of commitments: every one names the one before it.
  const chain = readChain(lines);
  r.entries = chain.entries;
  r.lines = lines;
  if (chain.name !== op.origin) chain.problems.unshift({ line: 1, reason: `chain is ${JSON.stringify(chain.name)}` });
  if (!direct) chain.entries.forEach((e) => {
    if (e.event !== 'chain.anchored' || !/^[0-9a-f]{64}$/.test(e.meta.commit ?? '') || !e.meta.epoch) chain.problems.push({ line: e.seq + 1, reason: 'not a commitment' });
  });
  if (chain.problems.length) {
    chain.problems.slice(0, 3).forEach((p) => fail(problemText(p, noun)));
    check(`${noun}のつながり`, 'fail', problemText(chain.problems[0], noun));
  } else check(`${noun}のつながり`, 'ok', direct ? `記録 ${lines.length} 件すべてが、ひとつ前の記録とつながっています。` : `区間ごとの要約 ${lines.length} 件すべてが、ひとつ前の要約とつながっています。`);
  r.lastEpoch = chain.entries.at(-1)?.meta.epoch;

  // 2. The checkpoint: the operator's signature, and the cosignature.
  let cp;
  try {
    cp = await verifyCheckpoint(note, operator, [witness]);
    check('運用者の署名', 'ok', `${op.name} の鍵による署名を確認しました。`);
  } catch (e) {
    const cosig = /^signature by /.test(e.message) && !e.message.startsWith(`signature by ${operator.name}:`);
    fail(cosig ? '連署の署名が正しくありません。' : '運用者の署名を確認できませんでした。');
    check(cosig ? '連署' : '運用者の署名', 'fail', `${cosig ? '連署の署名が正しくありません' : '運用者の署名を確認できませんでした'}（${e.message}）。`);
    return r;
  }
  r.size = cp.size;
  r.root = cp.root;

  const byWitness = cp.cosigned.find((c) => c.verifier === witness);
  r.witnessTime = byWitness?.time;
  if (byWitness) check('第三者の連署', 'ok', `${WN} の連署サーバーが ${when(byWitness.time * 1000)} に連署しました。`);
  else {
    if (r.verdict === 'ok') r.verdict = 'pending';
    check('第三者の連署', 'warn', `この時点の${noun}に対する ${WN} の連署が、まだありません。`);
  }

  // 3. What was signed is what is published.
  const leaves = lines.map((l) => leafHash(l));
  if (cp.size > lines.length) {
    fail(`署名された時点では ${cp.size} 件あった${noun}が、いまは ${lines.length} 件しか公開されていません。${noun}が削除されています。`);
    check('署名された内容との一致', 'fail', `署名は ${cp.size} 件に対するものですが、公開されている${noun}は ${lines.length} 件です。`);
  } else if (!equal(merkleRoot(leaves, cp.size), cp.root)) {
    fail(`公開されている${noun}が、署名された内容と一致しません。署名のあとで書き換えられています。`);
    check('署名された内容との一致', 'fail', `公開されている${noun}から計算した値が、署名された値と一致しません。`);
  } else check('署名された内容との一致', 'ok', `署名された ${cp.size} 件が、公開されている${noun}と一致します。`);

  // 4. What the witness last cosigned is still there.
  const held = status?.logs?.[op.origin];
  if (held) {
    let root;
    try {
      root = unb64(held.root);
    } catch {
      root = undefined;
    }
    if (held.size > lines.length) {
      fail(`${WN} が連署した時点では ${held.size} 件あった${noun}が、いまは ${lines.length} 件しか公開されていません。`);
      check(`${WN} の控えとの照合`, 'fail', `${WN} は ${held.size} 件の時点に連署していますが、公開されている${noun}は ${lines.length} 件です。`);
    } else if (!root || !equal(merkleRoot(leaves, held.size), root)) {
      fail(`公開されている${noun}が、${WN} が連署した内容と一致しません。`);
      check(`${WN} の控えとの照合`, 'fail', `${WN} が最後に連署した内容と、公開されている${noun}が一致しません。`);
    } else check(`${WN} の控えとの照合`, 'ok', `${WN} が最後に連署した時点（${when(held.time * 1000)}）の内容が、そのまま残っています。`);
  }
  return r;
}

const trusted = (r) => r.verdict === 'ok' || r.verdict === 'pending';

// ---- checking records handed over with their proofs ----

/** What a record is about: its event, its time, and the rest. Nothing here says where the record sits in the operator's chain. */
function parseBody(body) {
  const about = JSON.parse(body);
  const meta = {};
  for (const [k, v] of Object.entries(about)) if (typeof v === 'string' && k !== 'event' && k !== 'at') meta[k] = v;
  if (typeof about.event !== 'string' || typeof about.at !== 'string') throw new Error('not what a record is about');
  return { at: about.at, event: about.event, meta };
}

/**
 * Each record handed over becomes an entry with a state: `confirmed` (what
 * it says leads to a commitment the third party has cosigned), `waiting`
 * (its interval has not come, or has not been cosigned yet) or `failed` (it
 * does not lead to the commitment it names). The order is the one they were
 * made in: by their own time, and as handed over within a second.
 */
function checkBundle(r, bundle) {
  const out = [];
  for (const rec of bundle.records ?? []) {
    let e;
    try {
      e = parseBody(rec.body);
    } catch {
      out.push({ at: '', event: '', meta: {}, state: 'failed' });
      continue;
    }
    const a = rec.anchor;
    if (!a) e.state = 'waiting';
    else {
      const pub = r.entries[a.seq];
      let commit;
      try {
        commit = commitOf(rec.body, bundle.chain, a);
      } catch {
        commit = undefined;
      }
      if (!pub) e.state = 'waiting';
      else if (!commit || pub.meta.commit !== commit || pub.meta.epoch !== a.epoch) e.state = 'failed';
      else e.state = a.seq < r.size && r.witnessTime ? 'confirmed' : 'waiting';
    }
    out.push(e);
  }
  return out.map((e, i) => [e, i]).sort(([x, i], [y, j]) => (Date.parse(x.at) || 0) - (Date.parse(y.at) || 0) || i - j).map(([e]) => e);
}

// ---- the screens ----

const ICON = { ok: '✓', warn: '…', fail: '×', unavailable: '?', pending: '…', waiting: '…' };

function banner({ verdict, title, body = [], note, meta = [] }) {
  return h(
    'section',
    { class: `banner is-${verdict === 'waiting' ? 'pending' : verdict}`, 'data-verdict': verdict },
    h('div', { class: 'banner-icon', 'aria-hidden': 'true' }, ICON[verdict]),
    h('div', { class: 'banner-body' }, h('h1', null, title), body.map((x) => h('p', null, x)), note && h('p', { class: 'banner-note' }, note), meta.length > 0 && h('p', { class: 'banner-meta' }, meta.map((m) => h('span', null, m)))),
  );
}

const metaOf = (r) => (r.verdict === 'unavailable' ? [] : [r.op.name, r.witnessTime && `${WN} の連署 ${when(r.witnessTime * 1000)}`].filter(Boolean));

function logBanner(r, okBody) {
  const text = {
    ok: ['確認できました', [okBody]],
    pending: !r.lines.length
      ? r.direct
        ? ['最初の記録を待っています', ['この記録簿には、まだ記録がありません。']]
        : ['最初の要約を待っています', ['この記録は始まったばかりです。最初の区間が終わると、その区間の要約が第三者に預けられ、連署されます。']]
      : ['第三者の連署を待っています', [`運用者の署名は確認できましたが、この時点の${r.noun}に対する ${WN} の連署がまだありません。しばらくしてから、もう一度開いてください。`]],
    fail: ['確認できませんでした', r.reasons],
    unavailable: ['確認できませんでした', r.reasons],
  }[r.verdict];
  return banner({ verdict: r.verdict, title: text[0], body: text[1], meta: metaOf(r) });
}

function checksList(checks) {
  return h('ul', { class: 'checks' }, checks.map((c) => h('li', { class: `is-${c.state}` }, h('span', { class: 'mark', 'aria-hidden': 'true' }, ICON[c.state]), h('div', null, h('b', null, c.label), h('span', null, c.detail)))));
}

function rulesList(rules) {
  return h('ul', { class: 'rules' }, rules.map((rule) => h('li', null, h('b', null, rule.title), h('span', null, [rule.source && `根拠: ${rule.source}`, rule.within && `期限: ${span(rule.within)}以内`, rule.approval === 'required' && '実行の前に承認が必要', rule.state === 'waiting' && '第三者の確認待ち'].filter(Boolean).join(' ・ ')))));
}

function checksSection(r, rules) {
  return h('section', { class: 'card' }, h('h2', null, '確認した内容'), checksList(r.checks), rules?.length > 0 && [h('h3', null, '運用者が定めているルール'), rulesList(rules)]);
}

function explain() {
  return h(
    'section',
    { class: 'card explain' },
    h('h2', null, 'この確認でわかること'),
    h(
      'dl',
      null,
      h('dt', null, 'わかること'),
      h('dd', null, '記録が、連署の時刻にはすでに存在していたこと。そのあとで、書き換えられたり、消されたりしていないこと。'),
      h('dt', null, 'わからないこと'),
      h('dd', null, `記録の内容が事実かどうか。記録は運用者自身による申告です。${WN} は、申告があとから書き換えられていないことだけを確かめています。`),
      h('dt', null, `${WN} が持っているもの`),
      h('dd', null, '記録そのものは持っていません。預かっているのは、一定の間隔ごとの要約（その時点までの記録から計算した値）だけで、そこから記録の中身や件数は分かりません（記録そのものを公開している運用者の場合は、公開されている記録に連署しています）。この確認はすべてお使いのブラウザの中で行われます。リンクに含まれる確認用の番号はどこにも送られず、運用者には、そこから計算した照合用の値だけを送って、あなたの記録の内容と、その証明を受け取ります。'),
    ),
  );
}

const WAITING = '第三者の確認待ち（次の区間で確認されます）';

function timeline(mine, rules) {
  const plans = plansFor(rules, mine, Date.now());
  return h(
    'section',
    { class: 'card' },
    h('h2', null, 'あなたのお問い合わせの記録'),
    h('p', { class: 'lead' }, '日時は日本時間です。'),
    h(
      'ol',
      { class: 'timeline' },
      mine.map((e) => {
        const d = describe(e, rules);
        const by = d.by ?? e.meta.by;
        return h(
          'li',
          { class: [d.minor && 'is-minor', d.final && 'is-final', e.state === 'waiting' && 'is-waiting'].filter(Boolean).join(' '), 'data-event': e.event, 'data-state': e.state },
          h('span', { class: 'step' }, d.step),
          h('b', null, d.title),
          d.note && h('span', { class: 'note' }, d.note),
          h('span', { class: 'facts' }, [when(e.at), by && who(by)].filter(Boolean).map((x) => h('span', null, x)), e.state === 'waiting' && h('span', { class: 'tag' }, WAITING)),
        );
      }),
    ),
    plans.length > 0 && [
      h('h3', null, 'ルールにもとづく予定'),
      h(
        'ul',
        { class: 'plans' },
        plans.map((p) => {
          const state = p.done ? (p.late ? 'late' : 'done') : p.late ? 'overdue' : 'due';
          const label = { done: '完了', late: '期限後に完了', overdue: '期限超過', due: '予定' }[state];
          return h('li', { class: `is-${state}`, 'data-plan': state }, h('span', { class: 'badge' }, label), h('div', null, h('b', null, p.rule.title), h('span', null, p.done ? `${when(p.done.at, false)} に完了（期限 ${when(p.due, false)}）` : `期限 ${when(p.due, false)}`)));
        }),
      ),
    ],
  );
}

const again = () => h('button', { type: 'button', id: 'again' }, 'もう一度確認する');

/** A person's link: their own records, each checked against the commitments. */
async function personView(r, token) {
  if (!trusted(r)) return [logBanner(r), r.checks.length > 0 && checksSection(r), explain(), h('p', { class: 'back' }, again())];
  const item = hex(sha256(utf8(token))).slice(0, 32);
  let mine;
  let ruleEntries;
  try {
    const [a, b] = await Promise.all([getJson(`${r.base}/item?ref=${item}`), getJson(`${r.base}/rules`)]);
    mine = checkBundle(r, a).filter((e) => e.state === 'failed' || e.meta.item === item);
    ruleEntries = checkBundle(r, b);
  } catch {
    return [banner({ verdict: 'unavailable', title: '確認できませんでした', body: ['運用者のサーバーから記録を取得できませんでした。時間をおいて、もう一度開いてください。'], meta: metaOf(r) }), checksSection(r), explain(), h('p', { class: 'back' }, again())];
  }
  const failed = [...mine, ...ruleEntries].filter((e) => e.state === 'failed');
  const confirmed = mine.filter((e) => e.state === 'confirmed').length;
  const waiting = mine.filter((e) => e.state === 'waiting').length;
  if (failed.length) {
    r.checks.push({ label: 'あなたの記録の照合', state: 'fail', detail: `受け取った記録のうち ${failed.length} 件が、連署された要約と一致しません。記録が書き換えられている可能性があります。` });
    return [banner({ verdict: 'fail', title: '確認できませんでした', body: ['運用者から受け取った記録が、連署された要約と一致しません。記録が、要約を預けたあとで書き換えられている可能性があります。'], meta: metaOf(r) }), checksSection(r), explain(), h('p', { class: 'back' }, again())];
  }
  const rules = rulesOf(ruleEntries);
  if (!mine.length) {
    return [
      logBanner(r, 'この記録簿の要約は、作成されたあとに書き換えられていません。'),
      h('section', { class: 'card' }, h('h2', null, 'あなたのお問い合わせの記録'), h('p', { class: 'empty' }, h('b', null, 'まだ記録されていません。'), 'この確認用のリンクに対応する記録は、まだありません。送信の直後は、記録されるまで少し時間がかかることがあります。リンクが途中で切れていないかも確かめてください。')),
      checksSection(r, rules),
      explain(),
      h('p', { class: 'back' }, again()),
    ];
  }
  r.checks.push(
    waiting
      ? { label: 'あなたの記録の照合', state: confirmed ? 'ok' : 'warn', detail: `${confirmed ? `${confirmed} 件が、連署された要約に含まれていることを確かめました。` : ''}${waiting} 件は、まだ第三者の確認を待っています。` }
      : { label: 'あなたの記録の照合', state: 'ok', detail: `${confirmed} 件すべてが、連署された要約に含まれていることを確かめました。` },
  );
  let top;
  if (r.verdict === 'pending') top = logBanner(r);
  else if (mine[0].state === 'waiting') {
    top = banner({ verdict: 'waiting', title: '第三者の確認を待っています', body: ['受付は記録されています。第三者による確認は、一定の間隔でまとめて行われます。次の区間のあとに、もう一度開いてください。'], meta: metaOf(r) });
  } else {
    top = banner({ verdict: 'ok', title: '確認できました', body: ['この記録は、作成されたあとに書き換えられていません。'], note: waiting ? `新しい ${waiting} 件は、まだ第三者の確認を待っています。次の区間で確認されます。` : undefined, meta: metaOf(r) });
  }
  return [top, timeline(mine, rules), checksSection(r, rules), explain(), h('p', { class: 'back' }, again())];
}

// ---- what the operator's auditor left here ----

const FINDINGS = [
  ['overdue', '期限超過'],
  ['late', '期限後に完了'],
  ['unapproved', '承認なしの実行'],
  ['plan_mismatch', '承認と違う実行'],
  ['not_told', '通知の漏れ'],
  ['no_key', '対象が不明'],
];
const CHECKS = [
  ['records', '記録のつながり'],
  ['anchors', '要約との一致'],
  ['cosignature', '第三者の連署'],
];

/** Checks each stored statement against the registered auditor's key, here in the browser. */
async function verifyResults(op, results) {
  const out = [];
  for (const res of results ?? []) {
    const item = { received: res.received_at, valid: false };
    try {
      const auditor = (op.auditors ?? []).find((a) => a.id === res.credential?.id);
      if (!auditor) throw new Error('unregistered key');
      await verifyAssertion({ key: auditor.key, credential: res.credential, challenge: challengeFor(res.statement), origin: location.origin, rpId: location.hostname });
      const s = JSON.parse(res.statement);
      if (s.type !== 'audit-statement/v1' || s.origin !== op.origin) throw new Error('for another log');
      item.valid = true;
      item.statement = s;
      item.name = auditor.name;
    } catch {
      // shown as not verifying; what it says is not shown
    }
    out.push(item);
  }
  return out;
}

function resultItem(x) {
  if (!x.valid) {
    return h('li', { class: 'result is-invalid', 'data-result': 'invalid' }, h('div', { class: 'result-head' }, h('b', null, when(x.received, false)), h('span', { class: 'tag is-fail' }, '署名を確認できません')), h('p', null, 'この結果は、登録されている鍵による署名を確認できませんでした。署名のあとで内容が変わっているか、登録されていない鍵で署名されています。内容は表示しません。'));
  }
  const s = x.statement;
  const total = FINDINGS.reduce((n, [k]) => n + (s.findings[k] ?? 0), 0);
  const checksOk = CHECKS.every(([k]) => s.checks[k] === 'ok');
  return h(
    'li',
    { class: `result ${checksOk ? 'is-ok' : 'is-fail'}`, 'data-result': 'valid' },
    h('div', { class: 'result-head' }, h('b', null, when(s.at, false)), h('span', null, x.name), h('span', { class: 'tag is-ok' }, '署名を確認')),
    h('p', { class: 'covers' }, s.covers.through ? `${when(s.covers.through, false)} の区間までの記録を検証しました。` : '検証の時点で、連署された要約はまだありませんでした。'),
    h('ul', { class: 'result-checks' }, CHECKS.map(([k, label]) => h('li', { class: s.checks[k] === 'ok' ? 'is-ok' : 'is-fail' }, `${label}：${s.checks[k] === 'ok' ? '問題なし' : '問題あり'}`))),
    h('p', { class: 'result-sum' }, total ? `ルールに照らして、指摘が ${total} 件ありました。` : 'ルールに照らして、指摘はありませんでした。'),
    h('ul', { class: 'counts' }, FINDINGS.map(([k, label]) => h('li', { class: s.findings[k] ? 'has' : '' }, h('span', null, label), h('b', null, String(s.findings[k] ?? 0))))),
    s.note && h('p', { class: 'result-note' }, s.note),
  );
}

/** What anyone may see of a log: the commitments, the rules, and the auditor's results. */
async function overview(r) {
  const op = r.op;
  const out = [logBanner(r, 'この記録簿の要約は、作成されたあとに書き換えられていません。')];
  if (!trusted(r)) return [...out, r.checks.length > 0 && checksSection(r), h('p', { class: 'back' }, again(), h('a', { href: '#' }, '連署している記録の一覧へ'))];

  const [rulesBundle, results] = await Promise.all([getJson(`${r.base}/rules`).catch(() => undefined), getJson(`/results.json?o=${encodeURIComponent(op.origin)}`).catch(() => undefined)]);
  const ruleEntries = rulesBundle ? checkBundle(r, rulesBundle) : [];
  const badRules = ruleEntries.filter((e) => e.state === 'failed').length;
  const rules = badRules ? [] : rulesOf(ruleEntries);
  if (rulesBundle) r.checks.push(badRules ? { label: 'ルールの照合', state: 'fail', detail: `公開されているルールの記録のうち ${badRules} 件が、連署された要約と一致しません。` } : { label: 'ルールの照合', state: 'ok', detail: 'ルールの採用の記録が、連署された要約に含まれていることを確かめました。' });
  const verified = await verifyResults(op, results?.results);

  out.push(
    h(
      'section',
      { class: 'card' },
      h('h2', null, '連署の状態'),
      h(
        'dl',
        { class: 'facts-list' },
        h('dt', null, '最後に要約が預けられた区間'),
        h('dd', null, r.lastEpoch ? when(r.lastEpoch, false) : 'まだありません'),
        h('dt', null, `${WN} の連署`),
        h('dd', null, r.witnessTime ? when(r.witnessTime * 1000) : 'まだありません'),
        h('dt', null, '預けられた要約'),
        h('dd', null, `${r.lines.length} 件（区間ごとに 1 件）`),
      ),
      h('p', { class: 'lead' }, '運用者は、一定の間隔ごとに、その時点までの記録から計算した要約を 1 件ずつ預けます。その区間に出来事があってもなくても預けるので、要約の数や時刻から、出来事の件数は分かりません。'),
    ),
    h('section', { class: 'card', id: 'rules' }, h('h2', null, '採用されているルール'), !rulesBundle ? h('p', { class: 'empty' }, 'ルールを取得できませんでした。') : badRules ? h('p', { class: 'empty' }, 'ルールの記録が、連署された要約と一致しないため、表示しません。') : rules.length ? rulesList(rules) : h('p', { class: 'empty' }, 'まだ採用されているルールはありません。')),
    h(
      'section',
      { class: 'card', id: 'results' },
      h('h2', null, `${op.auditors?.[0]?.name ?? '内部監査室'}による検証結果`),
      h('p', { class: 'lead' }, '運用者の内部の監査担当が、このサイトで記録の全体を検証し、自分の鍵で署名して残した結果です。署名は、このページがいま確かめています。'),
      verified.length ? h('ul', { class: 'results' }, verified.map(resultItem)) : h('p', { class: 'empty' }, h('b', null, 'まだ検証結果はありません。')),
    ),
    h(
      'section',
      { class: 'card explain' },
      h('h2', null, 'ここで見えるもの、見えないもの'),
      h('p', null, '記録そのものは運用者の手もとにあり、ここには置かれていません。ここに預けられているのは、区間ごとの要約（記録のハッシュ）だけです。要約があるので、運用者は記録をあとから書き換えられませんが、要約から記録の中身や件数を知ることはできません。記録の全体を見て検証するのは、運用者自身の監査担当です。ただし、その結果が残る場所は運用者の外にあるので、運用者が結果を消したり直したりすることはできません。お問い合わせをした本人は、送信のときに受け取ったリンクから、自分の記録だけを確かめられます。'),
    ),
    checksSection(r),
    h('p', { class: 'back' }, again(), h('a', { href: '#' }, '連署している記録の一覧へ'), h('a', { href: `#o=${encodeURIComponent(op.origin)}&audit` }, '監査を担当する方へ')),
  );
  return out;
}

/** A log whose records are public: the records, checked; what kinds of event they hold; the latest of them. */
function directOverview(r) {
  const op = r.op;
  const back = h('p', { class: 'back' }, again(), h('a', { href: '#' }, '連署している記録の一覧へ'));
  const out = [logBanner(r, 'この記録は、作成されたあとに書き換えられていません。')];
  if (!trusted(r)) return [...out, r.checks.length > 0 && checksSection(r), back];

  const kinds = new Map();
  for (const e of r.entries) kinds.set(e.event || '（種類なし）', (kinds.get(e.event || '（種類なし）') ?? 0) + 1);
  const latest = r.entries.slice(-10).reverse();
  const last = r.entries.at(-1);

  out.push(
    h(
      'section',
      { class: 'card', id: 'state' },
      h('h2', null, '連署の状態'),
      h(
        'dl',
        { class: 'facts-list' },
        h('dt', null, '公開されている記録'),
        h('dd', null, `${r.lines.length} 件`),
        h('dt', null, '連署された範囲'),
        h('dd', null, r.witnessTime ? `最初から ${Math.min(r.size, r.lines.length)} 件目まで` : 'まだありません'),
        h('dt', null, `${WN} の連署`),
        h('dd', null, r.witnessTime ? when(r.witnessTime * 1000) : 'まだありません'),
        h('dt', null, '最新の記録'),
        h('dd', null, last?.at ? when(last.at) : 'まだありません'),
      ),
      r.lines.length > r.size && h('p', { class: 'lead' }, `新しい ${r.lines.length - r.size} 件は、まだ連署を待っています。次の連署で確かめられます。`),
    ),
    h(
      'section',
      { class: 'card', id: 'kinds' },
      h('h2', null, '記録されている出来事'),
      h('p', { class: 'lead' }, '出来事の種類は、運用者が決めた名前です。それぞれの記録には、対象のハッシュが入っています。'),
      h('ul', { class: 'counts' }, [...kinds].map(([kind, n]) => h('li', { 'data-kind': kind }, h('span', { class: 'mono' }, kind), h('b', null, String(n))))),
    ),
    h(
      'section',
      { class: 'card', id: 'latest' },
      h('h2', null, '新しい記録'),
      h('ol', { class: 'latest' }, latest.map((e) => h('li', { 'data-seq': String(e.seq) }, h('span', null, e.at ? when(e.at) : '日時不明'), h('span', { class: 'mono' }, e.event), h('span', { class: 'mono' }, `${e.seq} 番`)))),
      h('p', { class: 'actions' }, h('a', { href: `${r.base}/chain.jsonl` }, '記録の全体を見る'), op.site && h('a', { href: op.site }, '運用者の公開ページ')),
    ),
    h(
      'section',
      { class: 'card explain' },
      h('h2', null, 'ここで見えるもの、見えないもの'),
      h('p', null, `この運用者は、記録そのものを公開しています。記録が対応しているのはもともと公開しているデータで、記録の件数や時刻を隠す必要がないためです。${WN} の連署サーバーは、記録が増えるだけで、あとから書き換えられていないことを確かめて連署しています。`),
      h('p', null, '公開されているデータが記録と合っているかは、記録のハッシュと、運用者の公開ページのデータを照らし合わせて確かめます。記録の内容が事実かどうかは、ここでは分かりません。記録は運用者自身による申告です。'),
    ),
    checksSection(r),
    back,
  );
  return out;
}

// ---- the auditor: a key, the whole chain, and a signed result ----

const cred = (c) => ({ id: b64url(new Uint8Array(c.rawId)), authenticatorData: b64url(new Uint8Array(c.response.authenticatorData)), clientDataJSON: b64url(new Uint8Array(c.response.clientDataJSON)), signature: b64url(new Uint8Array(c.response.signature)) });

async function sign(challenge, ids) {
  const c = await navigator.credentials.get({ publicKey: { challenge: unb64url(challenge), rpId: location.hostname, allowCredentials: ids.map((id) => ({ type: 'public-key', id: unb64url(id) })), userVerification: 'preferred', timeout: 120000 } });
  return cred(c);
}

const STATUS = { waiting: '期限前', due: '対応が必要', overdue: '期限超過', done: '完了', done_late: '期限後に完了', excepted: '例外', withdrawn: '取り下げ' };

/** Everything an auditor checks, over the whole chain as the operator handed it over. */
async function auditChain(r, data) {
  const core = await import('./vendor/tsutome-core.js');
  const lines = data.records ?? [];
  const a = { checks: [], problems: [], lines: lines.length };
  const check = (label, state, detail) => a.checks.push({ label, state, detail });

  // 1. The records: every one names the one before it.
  const chain = core.parseChain(lines);
  if (chain.name !== data.chain && lines.length) chain.problems.unshift({ line: 1, reason: `chain is ${JSON.stringify(chain.name)}` });
  a.records = chain.problems.length ? 'failed' : 'ok';
  if (chain.problems.length) check('記録のつながり', 'fail', chain.problems.slice(0, 3).map((p) => `${p.line} 件目の記録: ${p.reason}`).join(' / '));
  else check('記録のつながり', 'ok', `${lines.length} 件すべてが、ひとつ前の記録とつながっています。`);

  // 2. The commitments: each one is the commitment to its interval's records, and the intervals leave no gap.
  const anchors = [...(data.anchors ?? [])].sort((x, y) => x.seq - y.seq);
  let covered = 0;
  let matched = 0;
  let cosigned = 0;
  for (const [i, x] of anchors.entries()) {
    const pub = r.entries[x.seq];
    let why;
    if (x.seq !== i) why = '要約の順番に抜けがあります';
    else if (x.from !== covered || !(x.to >= x.from) || x.to > lines.length) why = '区間の切れ目が合いません';
    else if (!pub) why = '公開されている要約にありません';
    else {
      let made;
      try {
        made = anchorOf(lines.slice(x.from, x.to), { chain: data.chain, epoch: x.epoch, nonce: x.nonce, pad: x.pad });
      } catch {
        made = undefined;
      }
      if (!made || made.commit !== pub.meta.commit || pub.meta.epoch !== x.epoch || made.size !== x.size) why = '記録から計算した値が、公開されている要約と一致しません';
    }
    if (why) {
      a.problems.push(`${i + 1} 件目の要約: ${why}。`);
      break;
    }
    covered = x.to;
    matched = i + 1;
    if (x.seq < r.size) cosigned = i + 1;
    a.through = x.epoch;
  }
  a.anchors = matched;
  a.unanchored = lines.length - covered;
  const anchorsOk = trusted(r) && !a.problems.length;
  a.anchorsState = anchorsOk ? 'ok' : 'failed';
  if (!trusted(r)) check('要約との一致', 'fail', '公開されている要約そのものを確認できませんでした。');
  else if (a.problems.length) check('要約との一致', 'fail', a.problems[0]);
  else check('要約との一致', 'ok', `${matched} 件の要約すべてが、その区間の記録から計算した値と一致します。${r.lines.length > matched ? `公開されている要約のうち新しい ${r.lines.length - matched} 件は、取得した記録よりあとの区間のものです。` : ''}`);
  a.cosignature = anchorsOk && r.witnessTime && cosigned === matched && matched > 0 ? 'ok' : 'failed';
  check('第三者の連署', a.cosignature === 'ok' ? 'ok' : r.verdict === 'fail' ? 'fail' : 'warn', a.cosignature === 'ok' ? `${WN} の連署サーバーが ${when(r.witnessTime * 1000)} に連署した要約に、ここまでの記録が含まれています。` : `検証した要約の一部または全部に、まだ ${WN} の連署がありません。`);

  // 3. What the rules ask, worked out from the records alone.
  const now = new Date();
  const { duties } = core.evaluate(chain.entries, now);
  a.findings = core.audit(chain.entries, now);
  a.duties = duties;
  a.counts = Object.fromEntries(FINDINGS.map(([k]) => [k, a.findings.filter((f) => f.kind === k).length]));
  return a;
}

function auditReport(a) {
  const dutyOf = (id) => a.duties.find((d) => d.id === id);
  const open = a.duties.filter((d) => ['waiting', 'due', 'overdue'].includes(d.status));
  const label = Object.fromEntries(FINDINGS);
  return [
    checksList(a.checks),
    h('dl', { class: 'facts-list' }, h('dt', null, '記録'), h('dd', null, `${a.lines} 件`), h('dt', null, '検証した要約'), h('dd', null, `${a.anchors} 件`), h('dt', null, 'まだ要約に入っていない記録'), h('dd', null, `${a.unanchored} 件${a.unanchored ? '（次の区間で入ります。この検証のための閲覧の記録も含まれます）' : ''}`)),
    h('h3', null, `ルールに照らした指摘（${a.findings.length} 件）`),
    a.findings.length
      ? h(
          'ul',
          { class: 'findings' },
          a.findings.map((f) => {
            const d = f.duty && dutyOf(f.duty);
            return h('li', { 'data-kind': f.kind }, h('span', { class: 'badge' }, label[f.kind] ?? f.kind), h('div', null, h('b', null, d ? d.title : f.message), h('span', null, [`${f.seq + 1} 件目の記録`, d?.about?.item && `対象 ${d.about.item.slice(0, 8)}`, d && `期限 ${when(d.dueAt, false)}`].filter(Boolean).join(' ・ '))));
          }),
        )
      : h('p', { class: 'empty' }, '指摘はありません。'),
    h('h3', null, `進行中の作業（${open.length} 件）`),
    open.length
      ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['状態', 'ルール', '対象', '期限'].map((x) => h('th', null, x)))), h('tbody', null, open.map((d) => h('tr', null, h('td', null, STATUS[d.status] ?? d.status), h('td', null, d.title), h('td', { class: 'mono' }, (d.about?.item ?? '').slice(0, 8)), h('td', null, when(d.dueAt, false)))))))
      : h('p', { class: 'empty' }, '進行中の作業はありません。'),
  ];
}

function auditView(op, witnessKey, status) {
  const auditors = op.auditors ?? [];
  const keyOut = h('div', { id: 'key-out' });
  const verifyOut = h('div', { id: 'verify-out' });
  const signOut = h('div', { id: 'sign-out' });
  const nameInput = h('input', { type: 'text', id: 'auditor-name', value: auditors[0]?.name ?? '内部監査室', maxlength: '40' });
  const makeKey = h('button', { type: 'button', id: 'make-key' }, auditors.length ? '別の鍵を作る' : '鍵を作る');
  const run = h('button', { type: 'button', id: 'run-audit', class: 'primary', disabled: auditors.length === 0 }, '検証する');
  const say = (el, kind, textValue) => el.replaceChildren(h('p', { class: `status is-${kind}`, role: 'status' }, textValue));
  const supported = Boolean(window.PublicKeyCredential && navigator.credentials);

  makeKey.addEventListener('click', async () => {
    try {
      const name = nameInput.value.trim() || '内部監査室';
      const c = await navigator.credentials.create({
        publicKey: {
          rp: { id: location.hostname, name: `記録の確認（${WN}）` },
          user: { id: crypto.getRandomValues(new Uint8Array(16)), name: `${name}（${op.origin}）`, displayName: name },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
          attestation: 'none',
          timeout: 120000,
        },
      });
      if (c.response.getPublicKeyAlgorithm() !== -7) throw new Error('この鍵の方式（ES256 以外）には対応していません。別の認証器で作り直してください。');
      const entry = { name, id: b64url(new Uint8Array(c.rawId)), key: b64(new Uint8Array(c.response.getPublicKey())), alg: -7 };
      const json = JSON.stringify(entry, null, 2);
      const copy = h('button', { type: 'button', id: 'copy-key' }, 'コピーする');
      copy.addEventListener('click', () => navigator.clipboard?.writeText(json).then(() => (copy.textContent = 'コピーしました'), () => undefined));
      keyOut.replaceChildren(h('p', { class: 'status is-ok', role: 'status' }, '鍵を作りました。秘密の部分は、この端末（または同期先のパスワード管理）から出ません。'), h('pre', { class: 'json', id: 'key-json' }, json), h('p', { class: 'actions' }, copy), h('p', { class: 'lead' }, 'この内容を、運用者の管理画面と、この連署サーバーの登録簿の両方に登録してもらってください。登録が済むと、下の「検証する」が使えるようになります。'));
    } catch (e) {
      say(keyOut, 'fail', e.name === 'NotAllowedError' ? '鍵の作成が取り消されました。' : `鍵を作れませんでした（${e.message}）。`);
    }
  });

  run.addEventListener('click', async () => {
    run.disabled = true;
    signOut.replaceChildren();
    say(verifyOut, 'busy', '運用者に本人であることを示して、記録を受け取っています…');
    try {
      const base = op.url.replace(/\/$/, '');
      const { challenge } = await post(`${base}/audit/challenge`);
      const credential = await sign(challenge, auditors.map((x) => x.id));
      const data = await post(`${base}/audit/chain`, { credential });
      // The public chain is read after the records, so that it is at least as new as they are.
      const r = await verifyAnchors(op, witnessKey, await getJson('/status.json').catch(() => status));
      const a = await auditChain(r, data);
      const me = auditors.find((x) => x.id === credential.id) ?? auditors[0];
      const ok = a.records === 'ok' && a.anchorsState === 'ok' && a.cosignature === 'ok';
      verifyOut.replaceChildren(
        h('p', { class: `status is-${ok ? 'ok' : 'fail'}`, role: 'status', id: 'audit-verdict', 'data-ok': String(ok) }, ok ? '検証できました。記録は、預けられた要約のとおりです。' : '検証で問題が見つかりました。下の内容を確かめてください。'),
        ...auditReport(a),
        h('details', null, h('summary', null, '公開されている要約の確認'), checksList(r.checks)),
      );
      signCard(a, r, me);
    } catch (e) {
      say(verifyOut, 'fail', e.name === 'NotAllowedError' ? '本人確認が取り消されました。' : `検証できませんでした（${e.message}）。`);
    } finally {
      run.disabled = false;
    }
  });

  function signCard(a, r, me) {
    const note = h('textarea', { id: 'audit-note', rows: '3', maxlength: '500', placeholder: '補足があれば書きます（500字まで）。個人の名前や、お問い合わせの内容は書かないでください。' });
    const go = h('button', { type: 'button', id: 'sign-result', class: 'primary' }, '結果に署名して残す');
    const out = h('div', { id: 'sign-status' });
    go.addEventListener('click', async () => {
      go.disabled = true;
      try {
        const statement = JSON.stringify({
          type: 'audit-statement/v1',
          origin: op.origin,
          auditor: me.name,
          at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
          covers: { anchors: a.anchors, root: r.root ? b64(r.root) : '', through: a.through ?? '' },
          checks: { records: a.records, anchors: a.anchorsState, cosignature: a.cosignature },
          findings: a.counts,
          ...(note.value.trim() ? { note: note.value.trim() } : {}),
        });
        const credential = await sign(challengeFor(statement), [me.id]);
        await post('/results', { statement, credential });
        signOut.replaceChildren(h('p', { class: 'status is-ok', role: 'status', id: 'signed' }, '結果を残しました。このサイトで、誰でも見られます。'), h('p', { class: 'actions' }, h('a', { href: `#o=${encodeURIComponent(op.origin)}` }, '公開されている結果を見る')));
      } catch (e) {
        say(out, 'fail', e.name === 'NotAllowedError' ? '署名が取り消されました。' : `結果を残せませんでした（${e.message}）。`);
        go.disabled = false;
      }
    });
    const total = a.findings.length;
    signOut.replaceChildren(
      h('p', null, '残る内容は、検証した範囲、三つの確認の結果、指摘の種類ごとの件数、補足です。記録の件数や、個々の記録は含まれません。'),
      h('ul', { class: 'counts' }, FINDINGS.map(([k, label]) => h('li', { class: a.counts[k] ? 'has' : '' }, h('span', null, label), h('b', null, String(a.counts[k]))))),
      h('p', { class: 'lead' }, total ? `指摘が ${total} 件あります。そのまま残せます。` : '指摘はありません。'),
      note,
      h('p', { class: 'actions' }, go),
      out,
    );
  }

  return [
    h('section', { class: 'intro' }, h('h1', null, '監査を担当する方へ'), h('p', null, `${op.name} の記録の全体を、このページで検証して、結果を残します。記録は運用者からお使いのブラウザに直接届き、このサイトには送られません。`)),
    !supported && h('p', { class: 'notice' }, 'このブラウザは、パスキー（端末に保存する鍵）に対応していません。対応しているブラウザで開いてください。'),
    h(
      'section',
      { class: 'card' },
      h('h2', null, '1. 鍵を用意する'),
      h('p', { class: 'lead' }, auditors.length ? `登録されている鍵：${auditors.map((x) => x.name).join('、')}（${auditors.length} 本）。すでに鍵をお持ちなら、この手順は要りません。` : 'まだ鍵が登録されていません。最初に一度だけ、この端末で鍵を作ります。'),
      h('p', { class: 'field' }, h('label', { for: 'auditor-name' }, '登録する名前'), nameInput),
      h('p', { class: 'actions' }, makeKey),
      keyOut,
    ),
    h('section', { class: 'card' }, h('h2', null, '2. 検証する'), h('p', { class: 'lead' }, auditors.length ? '運用者に鍵で本人であることを示し、記録の全体を受け取って、預けられた要約と突き合わせます。ルールに照らした指摘も、ここで計算します。' : '鍵が登録されると使えるようになります。'), h('p', { class: 'actions' }, run), verifyOut),
    h('section', { class: 'card' }, h('h2', null, '3. 結果に署名して残す'), h('p', { class: 'lead' }, '検証が済むと、ここで結果に署名できます。'), signOut),
    h('p', { class: 'back' }, h('a', { href: `#o=${encodeURIComponent(op.origin)}` }, '公開されている内容へ戻る')),
  ];
}

// ---- the list, and the way in ----

function listLogs(registry) {
  const ops = registry.operators ?? [];
  return [
    h('section', { class: 'intro' }, h('h1', null, '記録の確認'), h('p', null, '事業者が残した取り扱いの記録が、あとから書き換えられていないことを確かめるサイトです。確認用のリンクをお持ちの方は、そのリンクを開いてください。')),
    h(
      'section',
      { class: 'card' },
      h('h2', null, '連署している記録'),
      ops.length
        ? h('ul', { class: 'logs' }, ops.map((op) => h('li', null, h('a', { href: `#o=${encodeURIComponent(op.origin)}` }, h('b', null, op.name), h('span', { class: 'mono' }, op.origin), isDirect(op) && h('span', { class: 'tag' }, '記録を公開')))))
        : h('p', { class: 'empty' }, 'まだ登録されている記録はありません。'),
    ),
    explain(),
  ];
}

const unavailable = (text, extra) => banner({ verdict: 'unavailable', title: '確認できませんでした', body: [text], meta: extra ?? [] });

/** Puts the witness's operator on the page: the name in the text, the title, the logo, the footer. */
function brand(w = {}) {
  WN = w.short_name || w.operator || WN;
  const full = w.operator && w.short_name && w.operator !== w.short_name ? `${w.operator}（${w.short_name}）` : w.operator || w.short_name;
  document.title = `記録の確認 | ${w.short_name || w.operator || w.name || '連署サーバー'}`;
  const logo = document.querySelector('.site-header .logo img');
  if (logo && w.logo) {
    logo.src = w.logo;
    logo.alt = full || '';
    logo.hidden = false;
  }
  const about = document.getElementById('about');
  if (about && full) about.textContent = `${full}が運営する、第三者の連署サーバーと確認サイトです。` + about.dataset.rest;
  const copy = document.getElementById('copyright');
  if (copy && (w.copyright || w.operator)) copy.textContent = `© ${w.copyright || w.operator}`;
}

let run = 0;
async function main() {
  const mine = ++run;
  const params = new URLSearchParams(location.hash.slice(1));
  const origin = params.get('o');
  const token = params.get('t');
  const show = (nodes) => {
    if (mine !== run) return;
    app.replaceChildren(...nodes.flat().filter(Boolean));
    document.getElementById('again')?.addEventListener('click', main);
    document.body.dataset.state = 'done';
  };
  app.replaceChildren(h('p', { class: 'loading' }, '記録を確認しています…'));
  document.body.dataset.state = 'loading';

  let registry;
  let witnessKey;
  let status;
  try {
    const custom = LOCAL && new URLSearchParams(location.search).get('registry');
    [registry, witnessKey, status] = await Promise.all([getJson(custom || '/registry.json'), get('/witness.vkey'), getJson('/status.json').catch(() => undefined)]);
  } catch {
    return show([unavailable('確認に必要な情報を読み込めませんでした。時間をおいて、もう一度開いてください。')]);
  }

  brand(registry.witness);
  if (!origin) return show(listLogs(registry));
  const op = (registry.operators ?? []).find((o) => o.origin === origin);
  if (!op) return show([unavailable(`この記録は、${WN} の登録簿にありません。リンクが正しいか確かめてください。`, [h('span', { class: 'mono' }, origin)]), h('p', { class: 'back' }, h('a', { href: '#' }, '連署している記録の一覧へ'))]);

  if (isDirect(op)) return show(directOverview(await verifyAnchors(op, witnessKey, status)));
  if (params.has('audit')) return show(auditView(op, witnessKey, status));
  const r = await verifyAnchors(op, witnessKey, status);
  show(token ? await personView(r, token) : await overview(r));
}

window.addEventListener('hashchange', main);
main();
