/** Canonical Twitch raid / paywall identity. */
function buildTwitchUidContextMessage(userId) {
  const id = String(userId ?? '').trim();
  if (!id) return '';
  return `twitch:uid:${id}`;
}

/** Human-send identity from Helix login (never display_name). */
function buildTwitchLoginContextMessage(login) {
  const normalized = String(login ?? '').trim().toLowerCase();
  if (!normalized) return '';
  return `twitch:${normalized}`;
}

function parseTwitchHelixUser(bodyText) {
  try {
    const json = JSON.parse(bodyText);
    const user = json?.data?.[0];
    const userId = user?.id != null ? String(user.id).trim() : '';
    const login = user?.login != null ? String(user.login).trim().toLowerCase() : '';
    return { userId, login };
  } catch (_) {
    return { userId: '', login: '' };
  }
}

function parseTwitchProveSelector(username) {
  const raw = String(username ?? '').trim();
  const lower = raw.toLowerCase();
  if (lower.startsWith('uid:')) {
    const id = raw.slice(4).trim();
    return id ? { type: 'uid', id } : { type: 'invalid' };
  }
  if (!lower) return { type: 'invalid' };
  return { type: 'login', login: lower };
}

/**
 * Context from Helix extract only. Client username is a selector, not a preimage.
 * @returns {{ ok: true, contextMessage: string } | { ok: false, error: string }}
 */
function resolveTwitchContextMessage(username, helixUser) {
  const selector = parseTwitchProveSelector(username);
  const userId = String(helixUser?.userId ?? '').trim();
  const login = String(helixUser?.login ?? '').trim().toLowerCase();

  if (selector.type === 'uid') {
    if (!userId) {
      return { ok: false, error: 'Twitch user id not found in Helix /users response' };
    }
    if (userId !== selector.id) {
      return { ok: false, error: 'Twitch user id does not match prove username' };
    }
    return { ok: true, contextMessage: buildTwitchUidContextMessage(userId) };
  }

  if (selector.type === 'login') {
    if (!login) {
      return { ok: false, error: 'Twitch login not found in Helix /users response' };
    }
    if (login !== selector.login) {
      return { ok: false, error: 'Twitch login does not match prove username' };
    }
    return { ok: true, contextMessage: buildTwitchLoginContextMessage(login) };
  }

  return { ok: false, error: 'Invalid Twitch prove username' };
}

module.exports = {
  buildTwitchUidContextMessage,
  buildTwitchLoginContextMessage,
  parseTwitchHelixUser,
  parseTwitchProveSelector,
  resolveTwitchContextMessage,
};
