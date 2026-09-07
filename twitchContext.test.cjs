const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  parseTwitchHelixUser,
  resolveTwitchContextMessage,
} = require('./twitchContext.js');

const helixBody = JSON.stringify({
  data: [
    {
      id: '126247254',
      login: 'kurdypel',
      display_name: 'Kurdypel',
    },
  ],
});

test('parseTwitchHelixUser reads id and login, ignores display_name', () => {
  const user = parseTwitchHelixUser(helixBody);
  assert.deepEqual(user, { userId: '126247254', login: 'kurdypel' });
});

test('uid selector emits twitch:uid from extract', () => {
  const user = parseTwitchHelixUser(helixBody);
  const resolved = resolveTwitchContextMessage('uid:126247254', user);
  assert.deepEqual(resolved, { ok: true, contextMessage: 'twitch:uid:126247254' });
});

test('login selector emits twitch:login from extract, not display_name', () => {
  const user = parseTwitchHelixUser(helixBody);
  const resolved = resolveTwitchContextMessage('Kurdypel', user);
  assert.deepEqual(resolved, { ok: true, contextMessage: 'twitch:kurdypel' });
});

test('client username is not copied into context', () => {
  const user = parseTwitchHelixUser(helixBody);
  const resolved = resolveTwitchContextMessage('othertwitch', user);
  assert.equal(resolved.ok, false);
  assert.match(resolved.error, /does not match/);
});

test('uid selector rejects extract id mismatch', () => {
  const user = parseTwitchHelixUser(helixBody);
  const resolved = resolveTwitchContextMessage('uid:999', user);
  assert.equal(resolved.ok, false);
});
