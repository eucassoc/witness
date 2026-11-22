# witness

[deedlog](https://github.com/eucassoc/deedlog) のチェーンのための、連署サーバーと確認サイトです。
どの組織でも、ほかの組織のために立てられます。一般社団法人エンドユーザーコンピューティング協会
（EUCA）は <https://witness.euca.in> で運営しています（設定は
[eucassoc/witness.euca.in](https://github.com/eucassoc/witness.euca.in)）。自分で立てるときは
[連署サーバーを立てる](#連署サーバーを立てる) を見てください。

[English](README.md)

自分たちが行ったことを改ざんの分かる形で記録している組織（[deedlog](https://github.com/eucassoc/deedlog)
のチェーン）は、その記録に何度でも署名できます。しかし、自分の署名だけでは、明日、別の履歴に
署名し直すこともできます。この連署サーバーは、組織の外の立場から、見せられたものが増えただけで
あることを確かめたうえで連署します。

見せられるのは、記録そのものではありません。組織は記録を手もとに置いたまま、一定の間隔ごとに、
もう一つの公開のチェーンへ要約を1件足します。前回からあとに加わった記録のハッシュで、出来事が
あってもなくても預けます。連署サーバーが連署するのは、このチェーンです
（[c2sp.org/tlog-witness](https://c2sp.org/tlog-witness) のまま。`dlog cosign` がそのまま使えます）。
連署サーバーに分かるのは時間が経ったことだけで、組織が何件、いつ行ったかは分かりません。

誰に何が見えるか:

| | 見えるもの | 資格 |
|---|---|---|
| 記録の対象になっている本人 | 自分の記録の内容と、それが要約に含まれている証明 | 受け取ったリンク |
| 組織の監査担当 | すべての記録（このサイトの上の、自分のブラウザの中で） | ここと組織の両方に登録したパスキー |
| 誰でも | 採用されているルール、連署の状態、監査担当が署名した検証結果 | なし |
| 連署サーバーの運営者 | 区間ごとの要約と、監査担当の検証結果 | — |

監査担当は組織自身の人（内部監査室）です。件数を見てよい立場の人です。組織の外にあるのは、
要約と検証結果の置き場所です。組織は、要約の裏で記録を書き換えることも、検証結果を消したり
直したりすることもできません。

連署が示すのは、記録が書き換えられていないことです。記録の内容が事実であることは示しません。
記録は組織自身の申告です。

## 確認サイト

確認は、すべて見る人のブラウザの中で行います。

- `/#o=<origin>&t=<token>`: 本人のリンク。組織に `ref`（番号の SHA-256 の先頭32桁。番号そのものは
  どこにも送りません）の記録を求め、1件ずつ連署された要約と突き合わせて、平易な言葉で表示します。
  区間がまだ来ていない記録は、確認待ちとして表示します。
- `/#o=<origin>`: 誰でも。連署の状態、採用されているルール、監査担当の検証結果。検証結果の署名は、
  登録された鍵でその場で確かめます。
- `/#o=<origin>&audit`: 監査担当。パスキーを作る。それで組織に本人であることを示して記録の全体を
  受け取る。要約と突き合わせる。ルールに照らした指摘を、組織のサービスと同じコード
  （[tsutome](https://github.com/eucassoc/tsutome)）で計算する。結果に署名して、ここに残す。

## エンドポイント

| | |
|---|---|
| `POST /add-checkpoint` | c2sp.org/tlog-witness。`200` で連署の行、`409` で連署サーバーが持っているサイズ（`text/x.tlog.size`）、登録簿にない記録は `404`、運用者の署名を確認できないときは `403`、整合性の証明を確認できないときは `422`。 |
| `GET /witness.vkey` | 連署サーバーの検証用の鍵。 |
| `GET /status.json` | 各記録について最後に連署したチェックポイント: `{"witness": "<vkey>", "logs": {"<origin>": {"size", "root", "time"}}}`。 |
| `POST /results` | 監査担当が署名した検証結果: `{"statement": "<JSON の文字列>", "credential": {"id", "authenticatorData", "clientDataJSON", "signature"}}`。記録が登録されていて、パスキーがその監査担当のもので、署名が声明のハッシュに対するもので、このサイトで、声明の時刻から10分以内に作られていれば保管します。`201`、または理由つきの `4xx`。 |
| `GET /results.json?o=<origin>` | その記録について保管している検証結果。新しい順、200件まで。 |
| `GET /registry.json` | 連署する記録と、その監査担当の鍵の登録簿。 |

声明:

```json
{ "type": "audit-statement/v1", "origin": "dlm.example.com/contact", "auditor": "内部監査室",
  "at": "2026-11-19T03:25:00Z",
  "covers": { "anchors": 144, "root": "<チェックポイントのルート、base64>", "through": "2026-11-19T03:20:00Z" },
  "checks": { "records": "ok", "anchors": "ok", "cosignature": "ok" },
  "findings": { "overdue": 0, "late": 1, "unapproved": 0, "plan_mismatch": 0, "not_told": 0, "no_key": 0 },
  "note": "任意。500字まで" }
```

## 組織が用意するもの

登録簿の `url` の下に、`Access-Control-Allow-Origin: *` をつけて置きます。

- `GET /chain.jsonl`、`GET /checkpoint`: 公開のチェーン（名前は `origin`）。記録は
  `{event: "chain.anchored", epoch, commit}`。署名と連署のついたチェックポイント。
- `GET /item?ref=<16進32桁>`、`GET /rules`: `{origin, chain, records: [{body, anchor?: {seq, epoch, size, index, path, nonce, blind, record}}]}`。
  `body` は、記録の内容（出来事、時刻、識別用の番号）です。記録の subject のダイジェストの元になる
  JSON の文字列で、記録の行そのものは渡しません。公開のチェーンの `seq` 番の `commit` に行き着きます
  （[`public/deedlog.js`](public/deedlog.js) の `commitOf`）。`anchor` のない記録は、次の区間を待っています。
- `POST /audit/challenge`、続けて、そのチャレンジへのパスキーの署名をつけた `POST /audit/chain`:
  `{origin, chain, records: [line...], anchors: [{seq, epoch, from, to, size, nonce, pad}]}`。
- `GET /key`: 検証用の鍵。

## 記録を登録する

連署サーバーは、[`public/registry.json`](public/registry.json) にある記録にだけ連署します。
追加するには、`operators` に項目を足して（プルリクエスト、または管理者による編集）デプロイします。
[`registry.example.json`](registry.example.json) が例です。

```json
{
  "name": "例示株式会社 お問い合わせの取り扱い記録",
  "origin": "dlm.example.com/contact",
  "checkpoint_key": "dlm.example.com/contact+1a2b3c4d+AQ...",
  "url": "https://dlm.example.com/log",
  "auditors": [{ "name": "内部監査室", "id": "<鍵の識別子>", "key": "<公開鍵>", "alg": -7 }]
}
```

- `origin`: 公開のチェーンの名前。チェックポイントの鍵の名前でもあります。
- `checkpoint_key`: 運用者の検証用の鍵。
- `url`: 運用者が、上に挙げたものを置いている場所。
- `auditors`: 検証結果を保管して表示するパスキー。監査担当が確認サイト（`/#o=<origin>&audit`）で
  鍵を作ると、この JSON が表示されます。ここと組織の両方に登録します。

記録は、名前と鍵の組です。同じ名前を新しい鍵で登録し直すと、最初から始まります。登録簿から
なくなった記録について保管していたものは、消します。鍵を読めない項目や、鍵の名前が `origin`
と違う項目は受け付けません。

### 記録そのものを公開する場合

記録の件数や時刻を隠す必要のない運用者もいます。記録の対象がもともと公開しているデータ
（たとえば政治資金の帳簿）で、公開している1件1件を記録と突き合わせられることに意味がある
場合です。このような記録は `"kind": "direct"` で登録します。

```json
{
  "name": "例示党 公開している帳簿の更新の記録",
  "kind": "direct",
  "origin": "ledger.example.org/changes",
  "checkpoint_key": "ledger.example.org/changes+1a2b3c4d+AQ...",
  "url": "https://ledger.example.org/ledger",
  "site": "https://ledger.example.org/"
}
```

運用者は `url` に、`GET /chain.jsonl`（記録そのもの。名前が `origin` の deedlog のチェーン）と
`GET /checkpoint`（署名と連署のあるチェックポイント）を、`Access-Control-Allow-Origin: *` を付けて
置きます。連署サーバーの動きは同じで、区別もしません。確認サイトは、記録をチェックポイントと、
連署サーバーが最後に連署した内容に照らして確かめ、件数、出来事の種類、新しい記録を表示します。`site`
があれば、公開しているデータと突き合わせる場所としてリンクします。本人用のリンクと監査担当の
手順はありません。`kind` を書かなければ、上で説明した要約の方式です。

## 守れないもの

- 連署サーバーの運営者は、検証結果を出さなかったり、消したりできます。検証結果そのものは、記録簿に載せていません。
- ここで作ったパスキーは、このサイトのドメインに結びついています。サイトが移れば、監査担当は
  鍵を作り直します。
- 証明を受け取った人には、組織について二つのことが分かります。その区間の木の大きさ（2の累乗なので、
  その区間の記録の件数の上限）と、その中での記録の位置です。記録が組織のチェーンの何番目にあるか、
  チェーンの長さがどれだけかは分かりません。

## 連署サーバーの鍵

シークレット `WITNESS_KEY`（`dlog keygen -witness -name <WITNESS_NAME> -out witness` が書き出す
署名用の鍵）があれば、それで署名します。なければ、最初に使うときに鍵を作り、Durable Object の
保存領域に置きます。どちらの場合も、検証用の鍵は `/witness.vkey` にあります。
連署サーバーは鍵で識別されます。他の人が頼るようになる前に、シークレットを設定し、控えを取って
ください。

## 連署サーバーを立てる

連署サーバーに意味があるのは、連署する記録の持ち主とは別の人が動かしているときだけです。
誰かにとってその「別の人」になれる立場なら、このリポジトリで連署サーバーを立てられます。

### Cloudflare Workers（おすすめ）

このリポジトリは Cloudflare Workers で動かすように作ってあり、それがいちばんのおすすめです。

- **状態は一か所で、一つずつ処理される。** 連署サーバーの状態は1つの Durable Object にあり、
  届いた順に一つずつ処理します。連署サーバーは、食い違う二つのチェックポイントに連署しては
  いけません。ここでは、同時に届いた依頼のせいでそれが起きることはなく、整合性を保つべき
  データベースもありません。
- **手入れがいらない。** パッチを当てるサーバーも、更新する証明書も、いっぱいになるディスクも
  ありません。立てた人が担当を離れても動き続け、無料プランで足ります。連署サーバーは、
  続く限り役に立ちます。
- **鍵は外に出ない。** 連署の鍵は Durable Object の中で作るか、暗号化されたシークレットとして
  渡します。どのリポジトリにも、誰のパソコンにもありません。
- **動いているコードを誰でも読める。** 公開のリポジトリからデプロイするので、署名している
  コードを誰でも確かめられます。
- **戻すのはワンクリック。** デプロイはすべて残り、問題があればダッシュボード（Deployments）から
  前の版に戻せます。連署サーバーの状態には影響しません。

SQLite を使う Durable Object を1つと、静的ファイルを使います。どちらも無料プランで足ります。

### 手順

1. このリポジトリから自分のリポジトリを作る。フォークするか、同じ持ち主の下に置くときは
   空のリポジトリを作ってこのリポジトリを push し、このリポジトリを `upstream` として残す。
   自分のリポジトリには設定を、このリポジトリにはコードを置く形です。
2. 三つのファイルを変える。
   - [`wrangler.jsonc`](wrangler.jsonc): `name`（Worker の名前）、`routes`（自分のホスト名）、
     `WITNESS_NAME`（連署サーバーの名前。ふつうはホスト名と同じ）、`SITE_ORIGIN`。
   - [`public/registry.json`](public/registry.json): `witness`（`name` は `WITNESS_NAME` と同じ、
     `operator` は組織の名前、`short_name` は画面での呼び名、必要なら `copyright`、ロゴを
     出すときは `"logo": "/logo.png"`）と、連署する記録の `operators`（最初は空で構いません）。
   - ロゴとアイコン: `public/logo.png`（高さ 46 px で表示）と `public/favicon.png`。
3. Cloudflare のダッシュボードで Workers & Pages、Create、Import a repository から自分の
   リポジトリを選ぶ。既定のデプロイコマンド（`npx wrangler deploy`）で動きます。ホスト名の
   ゾーンが同じアカウントにあれば、ホスト名も割り当てられます。
4. 誰かが頼るようになる前に、鍵をどうするか決める（次の節）。そのうえで
   `https://<ホスト名>/witness.vkey` を公開する。

`WITNESS_NAME` と鍵は、連署サーバーそのものを表します。連署の一つ一つに刻まれるので、
長く使える名前を選び、あとから変えないでください。

### 鍵

既定では、最初に使うときに連署サーバーが鍵を作り、Durable Object に置きます。いちばん簡単で、
鍵は Cloudflare の外に出ません。ただし控えがないので、Worker やその保存領域を消すと連署サーバーは
失われ、新しい鍵で登録し直すことになります。何年も頼られる連署サーバーにするなら、鍵を自分で作り、
署名用の鍵をオフラインで保管したうえで、シークレット `WITNESS_KEY` として渡してください
（[連署サーバーの鍵](#連署サーバーの鍵)）。

### 更新

連署サーバーで動くのは、自分のリポジトリにあるコードです。このリポジトリの変更は、自分の
リポジトリに取り込んだときにだけ届きます。上流で何が起きても、自分の連署サーバーが止まることは
ありません。`main` の最新ではなくリリース（タグ）を、変更内容を読んでから取り込んでください。

```sh
git fetch upstream --tags
git log --oneline main..v0.2.0     # 何が変わったか
git merge v0.2.0                   # 設定のファイルは、このリポジトリでは項目を足す以外に変えません
```

自分の `main` も守るには:

- Worker の本番ブランチ（Settings の Build）を、CI が通ってから進めるブランチ（`release` など）に
  し、`main` は作業用にする。[`.github/workflows/ci.yml`](.github/workflows/ci.yml) の CI は、
  連署サーバー、ブラウザでの確認サイト、deedlog のツールとの突き合わせ、デプロイの試行を行います。
- そのブランチを保護し、変更には pull request と CI の成功を必須にする。
- それでも問題のある版がデプロイされたら、ダッシュボードから前の版に戻す。

## 開発

```sh
npm install
npm test                         # 連署サーバー、共通のコード、ブラウザでの確認サイト
DLOG=/path/to/dlog npm test      # deedlog のツールとも突き合わせる
npx wrangler dev --var SITE_ORIGIN:http://localhost:8787
node test/fixture.mjs            # サンプルの記録つきの確認サイト（http://localhost:8930）
npm run vendor                   # deedlog や tsutome を更新したあと: public/deedlog.js と public/vendor/tsutome-core.js を作り直す
```

確認サイトのテストは、Playwright があればブラウザで実行し、なければ飛ばします。
[`public/deedlog.js`](public/deedlog.js)（SHA-256、マークル木、署名つきノート、チェックポイント、連署、
要約）は deedlog の JavaScript 版（npm の [`deedlog`](https://github.com/eucassoc/deedlog/tree/main/js)）で、
開発と試験はそちらでしています。これと [`public/webauthn.js`](public/webauthn.js)（パスキーの署名の検証）は
依存がなく、連署サーバーと確認サイトが共有します。`public/deedlog.js` と `public/vendor/tsutome-core.js` は
パッケージから生成したもので、コミットしてあります。このサイトはビルドなしでデプロイするためです。

## ライセンス

Apache-2.0
