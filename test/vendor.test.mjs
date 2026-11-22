// public/deedlog.js is deedlog's JavaScript implementation, copied from the
// package by scripts/vendor.mjs. It is developed and tested in
// eucassoc/deedlog (js/); here it only has to be that file, unedited.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('public/deedlog.js is the deedlog package\'s file, as `npm run vendor` writes it', () => {
  const { version } = JSON.parse(read('../node_modules/deedlog/package.json'));
  const copy = read('../public/deedlog.js');
  const source = read('../node_modules/deedlog/deedlog.js');
  assert.ok(copy.endsWith(source), 'public/deedlog.js differs from the package: run `npm run vendor`');
  assert.match(copy.slice(0, copy.length - source.length), new RegExp(`from deedlog ${version.replaceAll('.', '\\.')} `));
});
