// A fetch stand-in for chat/e2ee.ts tests: the key routes chat/e2ee.ts calls, answered by
// crypto/fakeKeyServer.ts as one signed-in user, so the real HTTP mapping, status checks and
// retry wiring run against a server that checks signatures. block(path) holds or fails routes.
import { Conflict } from '../crypto/records';
import { FakeKeyServer } from '../crypto/fakeKeyServer';

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

/** Answers a request instead of the fake server; undefined lets it through. */
export type Block = (method: string, path: string) => Response | undefined | Promise<Response | undefined>;

export function httpFake(server: FakeKeyServer, userId: string, block: { fn?: Block } = {}) {
  const api = server.as(userId);
  const serve = route(server, api, userId, block);
  // As fetch: an abort rejects the request at once, whatever the server is doing.
  return (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signal = init?.signal;
    if (!signal) return serve(input, init);
    if (signal.aborted) return Promise.reject(signal.reason);
    return new Promise((resolve, reject) => {
      const stop = () => reject(signal.reason);
      signal.addEventListener('abort', stop, { once: true });
      serve(input, init).then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
    });
  };
}

function route(server: FakeKeyServer, api: ReturnType<FakeKeyServer['as']>, userId: string, block: { fn?: Block }) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'http://x');
    const path = url.pathname;
    const method = init?.method ?? 'GET';
    // The routes take the shapes chat/e2ee.ts sends; the fake server checks what matters.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body = (init?.body ? JSON.parse(String(init.body)) : {}) as any;
    const held = await block.fn?.(method, path);
    if (held) return held;
    try {
      const m = /^\/api\/v1\/keys\/devices\/([^/]+)(\/signature)?$/.exec(path);
      switch (`${method} ${path}`) {
        case 'POST /api/v1/keys/upload': {
          const r = await api.upload(body);
          return json({ one_time_key_count: r.count, has_fallback_key: r.fallback });
        }
        case 'POST /api/v1/keys/query':
          return json(await api.query(body.user_ids));
        case 'POST /api/v1/keys/claim':
          return json({ keys: await api.claim(body.devices) });
        case 'PUT /api/v1/to-device':
          await api.sendToDevice(body.device_id, body.messages);
          return new Response(null, { status: 204 });
        case 'GET /api/v1/to-device':
          return json({ messages: await api.mailbox(url.searchParams.get('device_id') ?? '') });
        case 'POST /api/v1/to-device/ack':
          await api.ack(body.device_id, body.ids);
          return new Response(null, { status: 204 });
        case 'GET /api/v1/keys/master':
          return json(await api.getMaster());
        case 'PUT /api/v1/keys/master':
          return json({ version: await api.putMaster(body) });
        case 'PUT /api/v1/keys/pins':
          await api.putPins(body.version, body.expected_counter, body.sealed, body.signature);
          return json({ counter: (body.expected_counter as number) + 1 });
        case 'POST /api/v1/keys/devices/list/reserve':
          return json(await api.reserveDeviceList(body.version, body.expected_epoch, body.digest));
        case 'PUT /api/v1/keys/devices/list':
          await api.putDeviceList(body.version, body.expected_epoch, body.epoch, body.device_ids, body.signature);
          return json({ epoch: body.epoch });
        case 'GET /api/v1/keys/backup': {
          const q = url.searchParams;
          const page = await api.getBackup(Number(q.get('version')), { room_id: q.get('after_room') ?? '', sender_key: q.get('after_sender') ?? '', session_id: q.get('after_session') ?? '' });
          return json({ version: Number(q.get('version')), ...page });
        }
        case 'PUT /api/v1/keys/backup': {
          const r = await api.putBackup(body.version, body.generation, body.sessions, body.signature);
          return json({ full: r.refused.length > 0, refused: r.refused });
        }
      }
      if (m && method === 'POST' && m[2]) {
        await api.signDevice(decodeURIComponent(m[1]), body.version, body.signature);
        return new Response(null, { status: 204 });
      }
      if (m && method === 'DELETE' && !m[2]) {
        // As the server: a device already gone is a 404.
        if (!server.devices.get(userId)?.delete(decodeURIComponent(m[1]))) return json({ error: 'Unknown device' }, 404);
        return new Response(null, { status: 204 });
      }
      const room = /^\/api\/v1\/rooms\/([^/]+)$/.exec(path);
      if (room && method === 'GET') {
        const id = decodeURIComponent(room[1]);
        const members = (await api.roomMembers(id)).map((u) => ({ room_id: id, user_id: u }));
        return json({ room: { id, kind: 'channel' }, member: { room_id: id, user_id: userId }, members });
      }
      return json({ error: `unexpected ${method} ${path}` }, 404);
    } catch (e) {
      if (e instanceof Conflict) return json({ error: e.message, ...(e.retryInMs !== undefined ? { retry_in_ms: e.retryInMs } : {}) }, 409);
      return json({ error: e instanceof Error ? e.message : 'failed' }, 400);
    }
  };
}
