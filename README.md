# witness

A witness and a verification page for [deedlog](https://github.com/eucassoc/deedlog)
chains, that any organization can run for others. The End User Computing
Association (EUCA) runs one at <https://witness.euca.in> (its settings are in
[eucassoc/witness.euca.in](https://github.com/eucassoc/witness.euca.in)); to
run your own, see [Running your own witness](#running-your-own-witness).

[日本語](README.ja.md)

An organization that keeps a tamper-evident record of what it did (a
[deedlog](https://github.com/eucassoc/deedlog) chain) can sign it as often as
it likes; signed by itself alone, it could still sign a different history
tomorrow. This witness is a party outside the organization that cosigns after
checking that what it is shown only grew.

What it is shown is not the record. The organization keeps its records to
itself and, at a fixed interval, appends one commitment to a second, public
chain: a fingerprint of the records added since the last one, deposited
whether or not anything happened. The witness cosigns that chain
([c2sp.org/tlog-witness](https://c2sp.org/tlog-witness), unchanged, so
`dlog cosign` works against it). It learns that time passes, and nothing
about how much the organization did or when.

Who sees what:

| | sees | by |
|---|---|---|
| A person the records are about | what their own records say, each with a proof that it was committed to | the link they were given |
| The organization's auditor | every record, in their browser on this site | a passkey registered here and with the organization |
| Anyone | the rules in force, the state of cosigning, the auditor's signed results | nothing |
| The witness's operator | one commitment per interval, and the auditor's results | — |

The auditor is the organization's own (its internal audit office): somebody
allowed to see how much was done. What is outside the organization is where
the commitments and the results are kept. The organization cannot rewrite its
records behind the commitments, and cannot remove or change a result.

A cosignature shows that a record was not rewritten. It does not show that
what the record says is true: records are the organization's own statements.

## The page

Everything is checked in the reader's browser.

- `/#o=<origin>&t=<token>`: a person's link. The page asks the organization
  for the records of `ref` (the first 32 hex digits of SHA-256 of the token;
  the token itself is sent nowhere), checks each against the cosigned
  commitments, and shows them in plain words. A record whose interval has not
  come yet is shown as waiting.
- `/#o=<origin>`: for anyone. The state of cosigning, the rules in force, and
  the auditor's results, each result's signature checked with the registered
  key.
- `/#o=<origin>&audit`: for the auditor. Make a passkey; sign in to the
  organization with it and receive the whole chain; check it against the
  commitments; work out what the rules ask, with the same code the
  organization's service uses ([tsutome](https://github.com/eucassoc/tsutome));
  sign the result and leave it here.

## Endpoints

| | |
|---|---|
| `POST /add-checkpoint` | c2sp.org/tlog-witness. `200` with the cosignature line; `409` with the size the witness holds (`text/x.tlog.size`); `404` for a log that is not in the registry; `403` when the operator's signature does not verify; `422` when the consistency proof does not. |
| `GET /witness.vkey` | The witness's verifier key. |
| `GET /status.json` | The last checkpoint cosigned for each log: `{"witness": "<vkey>", "logs": {"<origin>": {"size", "root", "time"}}}`. |
| `POST /results` | An auditor's signed result: `{"statement": "<JSON string>", "credential": {"id", "authenticatorData", "clientDataJSON", "signature"}}`. Kept if the log is registered, the passkey is one of its auditors', and the signature is over the hash of the statement, made on this site, within ten minutes of the statement's time. `201`, or `4xx` with the reason. |
| `GET /results.json?o=<origin>` | The results kept for a log, newest first (at most 200). |
| `GET /registry.json` | The logs the witness cosigns, and their auditors' keys. |

A statement:

```json
{ "type": "audit-statement/v1", "origin": "dlm.example.com/contact", "auditor": "Internal audit",
  "at": "2026-11-19T03:25:00Z",
  "covers": { "anchors": 144, "root": "<checkpoint root, base64>", "through": "2026-11-19T03:20:00Z" },
  "checks": { "records": "ok", "anchors": "ok", "cosignature": "ok" },
  "findings": { "overdue": 0, "late": 1, "unapproved": 0, "plan_mismatch": 0, "not_told": 0, "no_key": 0 },
  "note": "optional, at most 500 characters" }
```

## What the organization serves

At the `url` of its registry entry, with `Access-Control-Allow-Origin: *`:

- `GET /chain.jsonl`, `GET /checkpoint`: the public chain (named `origin`) of
  records `{event: "chain.anchored", epoch, commit}`, and its signed, cosigned
  checkpoint.
- `GET /item?ref=<32 hex>`, `GET /rules`: `{origin, chain, records: [{body, anchor?: {seq, epoch, size, index, path, nonce, blind, record}}]}`.
  `body` is what a record is about (its event, its time, its identifiers), as
  the JSON text the record's subject digest is of; the record's line is not
  handed out. It leads to `commit` of the public record `seq` (`commitOf` in
  [`public/deedlog.js`](public/deedlog.js)); a record without `anchor` waits for the
  next interval.
- `POST /audit/challenge`, then `POST /audit/chain` with a passkey signature
  over the challenge: `{origin, chain, records: [line...], anchors: [{seq, epoch, from, to, size, nonce, pad}]}`.
- `GET /key`: its verifier key.

## Registering a log

The witness cosigns only the logs in [`public/registry.json`](public/registry.json).
To add one, add an entry to `operators` (a pull request, or an edit by a
maintainer) and deploy; see [`registry.example.json`](registry.example.json).

```json
{
  "name": "Example Inc. inquiry handling record",
  "origin": "dlm.example.com/contact",
  "checkpoint_key": "dlm.example.com/contact+1a2b3c4d+AQ...",
  "url": "https://dlm.example.com/log",
  "auditors": [{ "name": "Internal audit", "id": "<credential id>", "key": "<public key>", "alg": -7 }]
}
```

- `origin`: the name of the public chain, which is also the name of the checkpoint key.
- `checkpoint_key`: the operator's verifier key.
- `url`: where the operator serves what is listed above.
- `auditors`: the passkeys whose results are kept and shown. The auditor
  makes the key on the page (`/#o=<origin>&audit`), which shows this JSON; it
  is registered here and with the organization.

A log is a name and a key. The same name registered under a new key starts
from nothing, and what was kept for a log no longer in the registry is deleted.
An entry whose key does not parse, or whose key name is not the origin, is
not accepted.

### A log that publishes its records

Some operators have nothing to hide in how many records they make or when:
what the records are about is published already, a ledger of political
funds for example, and the point is that anyone can hold each published
entry against its record. Such a log is registered with `"kind": "direct"`:

```json
{
  "name": "Example party: changes to the published ledger",
  "kind": "direct",
  "origin": "ledger.example.org/changes",
  "checkpoint_key": "ledger.example.org/changes+1a2b3c4d+AQ...",
  "url": "https://ledger.example.org/ledger",
  "site": "https://ledger.example.org/"
}
```

At `url` the operator serves `GET /chain.jsonl` (the records themselves, a
deedlog chain named `origin`) and `GET /checkpoint` (its signed, cosigned
checkpoint), with `Access-Control-Allow-Origin: *`. The witness cosigns it as
it does any other log; it never sees the difference. The page checks the
records against the checkpoint and against what the witness last cosigned,
and shows how many there are, of which kinds, and the latest; `site`, if
given, is linked as the place to hold the records against the published data.
There are no people's links and no auditor for such a log. Without `kind`, a
log is anchored, as described above.

## What this does not protect

- The witness's operator could withhold or delete a result. Results are not
  themselves logged.
- A passkey made here is bound to this site's domain. If the site moves, the
  auditors make new keys.
- A proof tells its holder two things about the organization: the size of the
  interval's tree, which is a power of two (so an upper bound on how many
  records the interval had), and the record's position in it. It does not
  tell where the record sits in the organization's chain, or how long that is.

## The witness's key

If the secret `WITNESS_KEY` is set (a signer key written by
`dlog keygen -witness -name <WITNESS_NAME> -out witness`), the witness signs
with it. Otherwise it makes a key on first use and keeps it in the Durable
Object's storage. Either way the verifier key is at `/witness.vkey`.
A witness is known by its key: set the secret, and keep a copy, before others
come to rely on it.

## Running your own witness

A witness is worth something only if it is not the organization whose
records it cosigns. If you are in a position to be that other party for
someone, you can run this one.

### Cloudflare Workers (recommended)

This repository is made to run on Cloudflare Workers, and that is the way we
recommend:

- **One state, one at a time.** Each witness's state lives in one Durable
  Object, which takes requests one after another. A witness must never
  cosign two checkpoints that disagree; here that cannot happen by two
  requests racing, and there is no database to keep consistent.
- **Nothing to look after.** No server to patch, no certificate to renew, no
  disk to fill. It keeps running when the person who set it up has moved on,
  and the free plan is enough. A witness is useful for as long as it lasts.
- **The key stays inside.** The witness's signing key is made inside the
  Durable Object, or given as an encrypted secret. It is in no repository
  and on nobody's laptop.
- **What runs is what anyone can read.** Deploying from a public repository
  means anyone can see the code that signs.
- **Going back is one click.** Each deployment is kept; a bad one is rolled
  back from the dashboard (Deployments), and the witness's state is not
  touched.

It needs one SQLite-backed Durable Object and static assets, both on the free
plan.

### Steps

1. Make a repository of your own from this one: fork it, or, if it would be
   under the same owner, create an empty repository and push this one to it,
   keeping this one as the remote `upstream`. Your repository holds your
   settings; this one holds the code.
2. Change three files:
   - [`wrangler.jsonc`](wrangler.jsonc): `name` (the Worker), `routes` (your
     host name), `WITNESS_NAME` (the witness's name, usually the same host
     name) and `SITE_ORIGIN`.
   - [`public/registry.json`](public/registry.json): `witness` (`name`, as
     `WITNESS_NAME`; `operator`, your organization's name; `short_name`, how
     the page refers to you; optional `copyright`;      `"logo": "/logo.png"` to show one) and `operators`, the logs you
     cosign (start with none).
   - Your logo and icon: `public/logo.png` (shown 46 px high) and
     `public/favicon.png`.
3. In the Cloudflare dashboard: Workers & Pages, Create, Import a repository,
   your repository. The default deploy command (`npx wrangler deploy`) works.
   The host name is attached if its zone is in the same account.
4. Decide about the key (below) before anyone relies on the witness. Then
   publish `https://<host>/witness.vkey`.

`WITNESS_NAME` and the key are what the witness is known by: they are in
every cosignature it makes. Choose a name you will keep, and do not change it
afterwards.

### The key

By default the witness makes its key on first use and keeps it in the
Durable Object. That is the simplest, and the key never leaves Cloudflare;
but there is no copy, and if the Worker or its storage is deleted the
witness is gone and has to be registered again under a new key. For a
witness others will rely on for years, make the key yourself, keep the
signer key offline, and give it to the Worker as the secret `WITNESS_KEY`
(see [The witness's key](#the-witnesss-key)).

### Updating

Your witness runs what your repository holds. A change here reaches it only
when you take it into yours: nothing upstream can stop your witness. Take
releases (tags) rather than whatever is on `main`, and read what changed:

```sh
git fetch upstream --tags
git log --oneline main..v0.2.0     # what changed
git merge v0.2.0                   # your settings are in files this repository does not change, except to add to them
```

To guard your own `main` as well:

- Set the Worker's production branch (Settings, Build) to a branch you
  advance only after CI passes, such as `release`, and keep `main` for work.
  The CI in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the
  witness, the page in a browser, deedlog's own tool against it, and a dry
  run of the deployment.
- Protect that branch, so that a change needs a pull request and a green CI.
- If a bad version is deployed anyway, roll back from the dashboard.

## Development

```sh
npm install
npm test                         # the witness, the shared code, the page in a browser
DLOG=/path/to/dlog npm test      # also against deedlog's own tool
npx wrangler dev --var SITE_ORIGIN:http://localhost:8787
node test/fixture.mjs            # the page with sample logs, at http://localhost:8930
npm run vendor                   # after updating deedlog or tsutome: rebuild public/deedlog.js and public/vendor/tsutome-core.js
```

The page tests run in a browser when Playwright is installed, and are skipped
when it is not. [`public/deedlog.js`](public/deedlog.js) (SHA-256, the Merkle tree,
signed notes, checkpoints, cosignatures, anchoring) is deedlog's JavaScript
implementation, the npm package
[`deedlog`](https://github.com/eucassoc/deedlog/tree/main/js), where it is
developed and tested; it and [`public/webauthn.js`](public/webauthn.js)
(checking a passkey's signature) have no dependencies and are shared by the
witness and the page. `public/deedlog.js` and `public/vendor/tsutome-core.js`
are generated from the packages and committed, because the site deploys
without a build step.

## License

Apache-2.0
