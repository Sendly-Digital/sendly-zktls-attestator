# sendly-zktls-attestator

HTTP API service for Sendly Payments functionality that combines:
- account verification via Reclaim Protocol;
- backend OAuth token exchange for social providers;
- zkTLS proof generation via the `zktls` CLI;

## What the service does

`sendly-zktls-attestator` acts as a backend adapter between the `Sendly` frontend and external providers (Twitter/X, GitHub, Telegram, LinkedIn, Instagram, Gmail, Twitch) to:

1. avoid storing sensitive secrets on the client;
2. issue/verify proofs via Reclaim and zkFetch;
3. generate zkTLS proofs for subsequent onchain logic.

## Technologies

- Node.js 18+
- Express 4
- `@reclaimprotocol/js-sdk`
- `@reclaimprotocol/zk-fetch`
- GramJS (`telegram`)
- `zktls` CLI (external binary)

## API (main routes)

### Reclaim / zkFetch
- `GET /api/reclaim/config` — builds proof request config for the selected platform and user.
- `POST /api/reclaim/verify` — verifies the received proof.
- `POST /api/reclaim/zkfetch/signature` — issues a session signature for zkFetch.
- `POST /api/reclaim/zkfetch/prove` — backend zkFetch proof generation.
- `POST /api/reclaim/callback` — endpoint for Reclaim server-to-server callbacks.

### zkTLS
- `POST /api/proof/generate` — runs `zktls prove` to generate a zkTLS proof.