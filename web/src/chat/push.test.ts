import { describe, expect, it } from 'vitest';
import { parseBootstrap } from './types';
import { getBrowserPushState } from './push';

describe('Web Push bootstrap parsing & browser state', () => {
  it('parses push config from bootstrap payload', () => {
    const boot = parseBootstrap({
      user: { id: 'u1', username: 'alice', display_name: 'Alice', role: 'user' },
      tenant: { id: 'default', slug: 'default', display_name: 'KyMessages' },
      rooms: [],
      active_calls: {},
      rtc: { sfu_available: false, ice_servers: [] },
      attachments: { available: true, max_upload_bytes: 1024, max_per_message: 5 },
      push: { available: true, vapid_public_key: 'BTestPublicKeyValue1234567890' },
    });
    expect(boot.push).toEqual({
      available: true,
      vapid_public_key: 'BTestPublicKeyValue1234567890',
    });
  });

  it('defaults push config safely when omitted', () => {
    const boot = parseBootstrap({
      user: { id: 'u1', username: 'alice', display_name: 'Alice', role: 'user' },
      tenant: { id: 'default', slug: 'default', display_name: 'KyMessages' },
      rooms: [],
    });
    expect(boot.push).toEqual({
      available: false,
      vapid_public_key: '',
    });
  });

  it('reports unsupported in non-push jsdom environment', async () => {
    const state = await getBrowserPushState({
      available: true,
      vapid_public_key: 'BTestPublicKeyValue1234567890',
    });
    expect(state).toEqual({ kind: 'unsupported' });
  });
});
