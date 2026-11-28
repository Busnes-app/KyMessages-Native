import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Chat } from './Chat';
import { HybridCallController } from '../rtc/hybridCall';
import { deliverKey, fakeEnvelope, heldOpenCount, holdFakeOpens, resetFakeE2EE, setFakeIdentity, setFakeStarted, setFakeUnavailable, storeKeySilently } from '../chat/e2eeFake';

// Pages run without the WebAssembly core; crypto/engine.test.ts covers the real one.
vi.mock('../chat/e2ee', () => import('../chat/e2eeFake'));

const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readyState = 1;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => this.onopen?.());
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
    this.onclose?.();
  }

  emit(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }
}

beforeEach(() => {
  FakeWebSocket.instances = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
});

afterEach(() => {
  resetFakeE2EE();
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.history.replaceState(null, '', '/');
});

describe('Native Chat page', () => {
  it('loads bootstrap rooms, renders messages, sends with Idempotency-Key, and streams live WS events', async () => {
    const sentRequests: { url: string; headers: Headers; body: string }[] = [];
    const onAuthRevoked = vi.fn();

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [
              {
                id: 'rm_gen',
                tenant_id: 'default',
                kind: 'channel',
                name: 'general',
                topic: 'Daily updates',
                is_private: false,
                last_seq: 1,
                created_by: 'u_alice',
                created_at: 1_700_000_000_000,
                role: 'owner',
                last_read_seq: 0,
                unread_count: 1,
                notify_mode: 'all',
              },
            ],
          });
        }
        if (url === '/api/v1/users') {
          return json({
            users: [
              { id: 'u_alice', username: 'alice', display_name: 'Alice' },
              { id: 'u_bob', username: 'bob', display_name: 'Bob' },
            ],
          });
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages') && method === 'GET') {
          return json({
            messages: [
              {
                id: 'msg_1',
                tenant_id: 'default',
                room_id: 'rm_gen',
                seq: 1,
                sender_id: 'u_bob',
                sender_name: 'Bob',
                encoding: 'plain_v1',
                body: 'Morning team!',
                created_at: 1_700_000_000_000,
                reactions: [],
              },
            ],
            has_more: false,
          });
        }
        if (url === '/api/v1/rooms/rm_gen/messages' && method === 'POST') {
          const headers = new Headers(init?.headers);
          const body = String(init?.body ?? '');
          sentRequests.push({ url, headers, body });
          const sent = JSON.parse(body) as { body: string; encoding: string };
          return json(
            {
              message: {
                id: 'msg_2',
                tenant_id: 'default',
                room_id: 'rm_gen',
                seq: 2,
                sender_id: 'u_alice',
                sender_name: 'Alice',
                encoding: sent.encoding,
                body: sent.body,
                created_at: 1_700_000_010_000,
                reactions: [],
              },
            },
            201,
          );
        }
        if (url === '/api/v1/rooms/rm_gen/read' && method === 'POST') {
          return json({ room_id: 'rm_gen', last_read_seq: 2 });
        }
        return json({ error: `unexpected ${method} ${url}` }, 404);
      }),
    );

    render(<Chat onAuthRevoked={onAuthRevoked} />);

    // Renders bootstrap room & history message.
    expect(await screen.findByText('Morning team!')).toBeTruthy();
    expect(screen.getByText('Busnes HQ')).toBeTruthy();
    expect(screen.getByText('Live')).toBeTruthy();

    // Send a message through the composer.
    const input = screen.getByLabelText('Message input');
    fireEvent.change(input, { target: { value: 'Hello from native UI!' } });
    fireEvent.submit(input.closest('form')!);

    expect(await screen.findByText('Hello from native UI!')).toBeTruthy();
    expect(sentRequests).toHaveLength(1);
    expect(sentRequests[0].headers.get('Idempotency-Key')).toBeTruthy();
    // The text leaves sealed; the legacy plaintext history says what it is.
    const posted = JSON.parse(sentRequests[0].body) as { body: string; encoding: string };
    expect(posted.encoding).toBe('e2ee_room_v1');
    expect(sentRequests[0].body).not.toContain('Hello from native UI!');
    expect(screen.getByText('Sent before encryption')).toBeTruthy();

    // Stream a live WebSocket message & typing & reaction event.
    const ws = FakeWebSocket.instances[0];
    expect(ws).toBeDefined();

    act(() => {
      ws.emit({ t: 'typing', room: 'rm_gen', d: { user_id: 'u_bob', active: true } });
    });
    expect(await screen.findByText('Bob is typing…')).toBeTruthy();

    act(() => {
      ws.emit({
        t: 'message.new',
        room: 'rm_gen',
        seq: 3,
        d: {
          id: 'msg_3',
          tenant_id: 'default',
          room_id: 'rm_gen',
          seq: 3,
          sender_id: 'u_bob',
          sender_name: 'Bob',
          encoding: 'e2ee_room_v1',
          body: fakeEnvelope({ room_id: 'rm_gen', type: 'text', body: 'Live over WebSocket!' }, 's_bob'),
          created_at: 1_700_000_020_000,
          reactions: [],
        },
      });
    });

    // Bob's room key has not arrived yet; the message opens when it does.
    expect(await screen.findByText("Waiting for this message's key")).toBeTruthy();
    act(() => deliverKey('s_bob'));
    expect(await screen.findByText('Live over WebSocket!')).toBeTruthy();
    expect(screen.queryByText("Waiting for this message's key")).toBeNull();
    // Typing indicator clears automatically when Bob's message arrives.
    expect(screen.queryByText('Bob is typing…')).toBeNull();

    // Reaction pushed via WebSocket updates pill immediately.
    act(() => {
      ws.emit({
        t: 'reaction.set',
        room: 'rm_gen',
        d: { message_id: 'msg_3', user_id: 'u_bob', emoji: '🎉', added: true },
      });
    });
    expect(await screen.findByLabelText('🎉 1')).toBeTruthy();

    // A message read before the device started says so, then shows its real outcome once it is up.
    setFakeUnavailable(true);
    act(() => {
      ws.emit({
        t: 'message.new',
        room: 'rm_gen',
        seq: 4,
        d: {
          id: 'msg_4', tenant_id: 'default', room_id: 'rm_gen', seq: 4, sender_id: 'u_bob', sender_name: 'Bob',
          encoding: 'e2ee_room_v1', body: fakeEnvelope({ room_id: 'rm_other', type: 'text', body: 'moved here' }, 's_bob'),
          created_at: 1_700_000_030_000, reactions: [],
        },
      });
    });
    expect(await screen.findByText(/Encryption is not available in this browser yet\./)).toBeTruthy();
    setFakeUnavailable(false);
    act(() => deliverKey('s_bob'));
    expect(await screen.findByText(/This message was encrypted for another room\./)).toBeTruthy();
    expect(screen.queryByText(/Encryption is not available in this browser yet\./)).toBeNull();

    // A deletion that lands while a retried open is still running stays deleted.
    act(() => {
      ws.emit({
        t: 'message.new',
        room: 'rm_gen',
        seq: 5,
        d: {
          id: 'msg_5', tenant_id: 'default', room_id: 'rm_gen', seq: 5, sender_id: 'u_bob', sender_name: 'Bob',
          encoding: 'e2ee_room_v1', body: fakeEnvelope({ room_id: 'rm_gen', type: 'text', body: 'removed by a moderator' }, 's_mod'),
          created_at: 1_700_000_040_000, reactions: [],
        },
      });
    });
    expect(await screen.findByText("Waiting for this message's key")).toBeTruthy();
    const release = holdFakeOpens();
    act(() => deliverKey('s_mod'));
    act(() => {
      ws.emit({ t: 'message.delete', room: 'rm_gen', seq: 6, d: { id: 'msg_5', deleted_at: 1_700_000_050_000 } });
    });
    expect(await screen.findByText('Message deleted')).toBeTruthy();
    await act(async () => {
      release();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(screen.queryByText('removed by a moderator')).toBeNull();
    expect(screen.getByText('Message deleted')).toBeTruthy();

    // A key that lands after a message was opened but before it is shown still opens it.
    const releaseRace = holdFakeOpens();
    act(() => {
      ws.emit({
        t: 'message.new',
        room: 'rm_gen',
        seq: 7,
        d: {
          id: 'msg_7', tenant_id: 'default', room_id: 'rm_gen', seq: 7, sender_id: 'u_bob', sender_name: 'Bob',
          encoding: 'e2ee_room_v1', body: fakeEnvelope({ room_id: 'rm_gen', type: 'text', body: 'raced its key' }, 's_race'),
          created_at: 1_700_000_060_000, reactions: [],
        },
      });
    });
    // The open has read the store (no key yet) and is still in flight: no row exists to retry.
    await waitFor(() => expect(heldOpenCount()).toBe(1));
    await act(async () => {
      storeKeySilently('s_race');
      releaseRace();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(await screen.findByText('raced its key')).toBeTruthy();

    // Likewise a message opened before the device was up, when the device starts before it shows.
    setFakeUnavailable(true);
    const releaseStart = holdFakeOpens();
    act(() => {
      ws.emit({
        t: 'message.new',
        room: 'rm_gen',
        seq: 8,
        d: {
          id: 'msg_8', tenant_id: 'default', room_id: 'rm_gen', seq: 8, sender_id: 'u_bob', sender_name: 'Bob',
          encoding: 'e2ee_room_v1', body: fakeEnvelope({ room_id: 'rm_gen', type: 'text', body: 'opened once the device was up' }, 's_race'),
          created_at: 1_700_000_070_000, reactions: [],
        },
      });
    });
    await waitFor(() => expect(heldOpenCount()).toBe(1));
    await act(async () => {
      setFakeUnavailable(false);
      storeKeySilently('s_race'); // the device came up, bumping the generation, with no row yet
      releaseStart();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(await screen.findByText('opened once the device was up')).toBeTruthy();

    // Instant auth revocation notifies parent shell.
    act(() => {
      ws.emit({ t: 'auth.revoked' });
    });
    await waitFor(() => expect(onAuthRevoked).toHaveBeenCalledTimes(1));
  });

  it('offers one-click #general creation when workspace has no rooms yet', async () => {
    let created = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_admin', username: 'admin', display_name: 'Admin', role: 'admin' },
            tenant: { id: 'default', slug: 'default', display_name: 'KyMessages', plan: 'self_hosted' },
            rooms: [],
          });
        }
        if (url === '/api/v1/users') return json({ users: [] });
        if (url === '/api/v1/rooms' && method === 'POST') {
          created = true;
          return json(
            {
              room: {
                id: 'rm_new',
                tenant_id: 'default',
                kind: 'channel',
                name: 'general',
                topic: 'Team-wide announcements and everyday conversation',
                is_private: false,
                last_seq: 0,
                created_by: 'u_admin',
                created_at: Date.now(),
              },
            },
            201,
          );
        }
        if (url === '/api/v1/rooms' && method === 'GET') {
          return json({
            rooms: created
              ? [
                  {
                    id: 'rm_new',
                    tenant_id: 'default',
                    kind: 'channel',
                    name: 'general',
                    topic: 'Team-wide announcements and everyday conversation',
                    is_private: false,
                    last_seq: 0,
                    created_by: 'u_admin',
                    created_at: Date.now(),
                    role: 'owner',
                    last_read_seq: 0,
                    unread_count: 0,
                    notify_mode: 'all',
                  },
                ]
              : [],
          });
        }
        if (url.startsWith('/api/v1/rooms/rm_new/messages')) {
          return json({ messages: [], has_more: false });
        }
        return json({ error: 'not found' }, 404);
      }),
    );

    render(<Chat />);
    const btn = await screen.findByRole('button', { name: 'Create #general' });
    fireEvent.click(btn);
    expect(await screen.findByRole('heading', { name: 'Welcome to #general' })).toBeTruthy();
  });

  it('offers encryption setup and device verification with no room at all', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_admin', username: 'admin', display_name: 'Admin', role: 'admin' },
            tenant: { id: 'default', slug: 'default', display_name: 'KyMessages', plan: 'self_hosted' },
            rooms: [],
          });
        }
        if (url === '/api/v1/users') return json({ users: [] });
        if (url === '/api/v1/rooms') return json({ rooms: [] });
        return json({ error: 'not found' }, 404);
      }),
    );
    setFakeIdentity({ state: 'none', quarantined: false });
    const { unmount } = render(<Chat />);
    fireEvent.click(await screen.findByRole('button', { name: 'Set up encryption' }));
    expect(await screen.findByText('Save your recovery key')).toBeTruthy();
    unmount();
    setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false });
    render(<Chat />);
    expect(await screen.findByRole('button', { name: 'Verify a device' })).toBeTruthy();
  });

  it('makes a mounted page usable once a failed encryption start-up recovers, clearing only its error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_admin', username: 'admin', display_name: 'Admin', role: 'admin' },
            tenant: { id: 'default', slug: 'default', display_name: 'KyMessages', plan: 'self_hosted' },
            rooms: [],
          });
        }
        if (url === '/api/v1/users') return json({ users: [] });
        if (url === '/api/v1/rooms') return json({ rooms: [] });
        return json({ error: 'not found' }, 404);
      }),
    );
    setFakeIdentity({ state: 'none', quarantined: false });
    setFakeStarted(false);
    render(<Chat />);
    expect(await screen.findByText(/Encryption could not start in this browser/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Set up encryption' })).toBeNull();
    // The retry brings the device up without a reload.
    act(() => setFakeStarted(true));
    expect(await screen.findByRole('button', { name: 'Set up encryption' })).toBeTruthy();
    await waitFor(() => expect(screen.queryByText(/Encryption could not start in this browser/)).toBeNull());
  });

  it('says why an encrypted send from an unverified device failed, and sends on retry once verified', async () => {
    const posts: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [{ id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '', is_private: false, last_seq: 0, created_by: 'u_alice', created_at: 1_700_000_000_000, role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all' }],
          });
        }
        if (url === '/api/v1/users') return json({ users: [{ id: 'u_alice', username: 'alice', display_name: 'Alice' }] });
        if (url.startsWith('/api/v1/rooms/rm_gen/messages') && method === 'GET') return json({ messages: [], has_more: false });
        if (url === '/api/v1/rooms/rm_gen/messages' && method === 'POST') {
          const sent = JSON.parse(String(init?.body)) as { body: string; encoding: string };
          posts.push(sent.encoding);
          return json({ message: { id: 'msg_1', tenant_id: 'default', room_id: 'rm_gen', seq: 1, sender_id: 'u_alice', sender_name: 'Alice', encoding: sent.encoding, body: sent.body, created_at: 1_700_000_010_000, reactions: [] } }, 201);
        }
        if (url === '/api/v1/rooms/rm_gen/read' && method === 'POST') return json({ room_id: 'rm_gen', last_read_seq: 1 });
        return json({ error: `unexpected ${method} ${url}` }, 404);
      }),
    );
    setFakeIdentity({ state: 'unverified', fingerprint: 'ab'.repeat(32), quarantined: false });
    render(<Chat />);
    const input = await screen.findByLabelText('Message input');
    fireEvent.change(input, { target: { value: 'not to no one' } });
    fireEvent.submit(input.closest('form')!);
    expect((await screen.findByText(/Failed to send:/)).textContent).toMatch(/verify this device/i);
    expect(posts).toEqual([]);
    // The gate offers the way out; once verified, Retry sends it.
    expect(screen.getByRole('button', { name: 'Verify this device' })).toBeTruthy();
    act(() => setFakeIdentity({ state: 'verified', fingerprint: 'ab'.repeat(32), restoring: false, backupFull: false }));
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(posts).toEqual(['e2ee_room_v1']));
    await waitFor(() => expect(screen.queryByText(/Failed to send:/)).toBeNull());
  });

  it('opens the direct message a suite #dm= link names', async () => {
    const dmBodies: string[] = [];
    const dmRoom = {
      id: 'rm_dm',
      tenant_id: 'default',
      kind: 'dm',
      name: 'Bob',
      topic: '',
      is_private: true,
      last_seq: 0,
      created_by: 'u_alice',
      created_at: Date.now(),
    };
    window.history.replaceState(null, '', '/#dm=u_bob');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'KyMessages', plan: 'self_hosted' },
            rooms: [],
          });
        }
        if (url === '/api/v1/users') return json({ users: [] });
        if (url === '/api/v1/rooms' && method === 'POST') {
          dmBodies.push(String(init?.body ?? ''));
          return json({ room: dmRoom, created: true }, 201);
        }
        if (url === '/api/v1/rooms' && method === 'GET') {
          return json({
            rooms: dmBodies.length ? [{ ...dmRoom, role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all' }] : [],
          });
        }
        if (url.startsWith('/api/v1/rooms/rm_dm')) return json({ messages: [], has_more: false });
        return json({ error: 'not found' }, 404);
      }),
    );

    render(<Chat />);
    await waitFor(() => expect(dmBodies).toEqual([JSON.stringify({ kind: 'dm', dm_user_id: 'u_bob' })]));
    await waitFor(() => expect(window.location.hash).toBe('#room=rm_dm'));
  });

  it('aborts and deletes a staged attachment removed while its upload is still in flight', async () => {
    let resolveUpload!: (res: Response) => void;
    let uploadSignal: AbortSignal | undefined;
    const deletedUrls: string[] = [];

    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return Promise.resolve(
            json({
              user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
              tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
              rooms: [
                {
                  id: 'rm_gen',
                  tenant_id: 'default',
                  kind: 'channel',
                  name: 'general',
                  topic: '',
                  is_private: false,
                  last_seq: 0,
                  created_by: 'u_alice',
                  created_at: Date.now(),
                  role: 'owner',
                  last_read_seq: 0,
                  unread_count: 0,
                  notify_mode: 'all',
                },
              ],
              attachments: { max_upload_bytes: 10 * 1024 * 1024, max_per_message: 10 },
            }),
          );
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return Promise.resolve(json({ messages: [], has_more: false }));
        }
        if (url === '/api/v1/rooms/rm_gen/attachments?encrypted=1' && method === 'POST') {
          uploadSignal = init?.signal ?? undefined;
          return new Promise<Response>((resolve) => {
            resolveUpload = resolve;
          });
        }
        if (url.startsWith('/api/v1/attachments/') && method === 'DELETE') {
          deletedUrls.push(url);
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(json({ error: 'not found' }, 404));
      }),
    );

    const { container } = render(<Chat />);
    await screen.findByRole('heading', { name: 'Welcome to #general' });

    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeTruthy();
    const file = new File(['hello world'], 'report.txt', { type: 'text/plain' });
    fireEvent.change(fileInput, { target: { files: [file] } });

    const removeBtn = await screen.findByRole('button', { name: 'Remove report.txt' });
    // The ciphertext upload starts once encryption finishes.
    await waitFor(() => expect(uploadSignal?.aborted).toBe(false));

    // User removes chip while upload is still in flight.
    fireEvent.click(removeBtn);
    expect(uploadSignal?.aborted).toBe(true);

    // Even if the server had already finished and resolves with 201, the client must DELETE it.
    await act(async () => {
      resolveUpload(
        json(
          {
            attachment: {
              id: 'att_late_orphan',
              tenant_id: 'default',
              room_id: 'rm_gen',
              uploader_id: 'u_alice',
              filename: 'report.txt',
              mime_type: 'text/plain',
              size_bytes: 11,
              sha256_hex: 'a'.repeat(64),
              created_at: Date.now(),
            },
          },
          201,
        ),
      );
    });

    await waitFor(() => {
      expect(deletedUrls).toEqual(['/api/v1/attachments/att_late_orphan']);
    });
  });

  it('restores staged uploads after a reload so they can be removed', async () => {
    const deletedUrls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return Promise.resolve(
            json({
              user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
              tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
              rooms: [
                {
                  id: 'rm_gen',
                  tenant_id: 'default',
                  kind: 'channel',
                  name: 'general',
                  topic: '',
                  is_private: false,
                  last_seq: 0,
                  created_by: 'u_alice',
                  created_at: Date.now(),
                  role: 'owner',
                  last_read_seq: 0,
                  unread_count: 0,
                  notify_mode: 'all',
                },
              ],
              attachments: { max_upload_bytes: 10 * 1024 * 1024, max_per_message: 10 },
            }),
          );
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return Promise.resolve(json({ messages: [], has_more: false }));
        }
        if (url === '/api/v1/rooms/rm_gen/attachments' && method === 'GET') {
          return Promise.resolve(
            json({
              attachments: [
                {
                  id: 'att_left_staged',
                  tenant_id: 'default',
                  room_id: 'rm_gen',
                  uploader_id: 'u_alice',
                  filename: 'notes.txt',
                  mime_type: 'text/plain',
                  size_bytes: 5,
                  sha256_hex: 'b'.repeat(64),
                  created_at: Date.now(),
                },
              ],
            }),
          );
        }
        if (url.startsWith('/api/v1/attachments/') && method === 'DELETE') {
          deletedUrls.push(url);
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(json({ error: 'not found' }, 404));
      }),
    );

    render(<Chat />);
    fireEvent.click(await screen.findByRole('button', { name: 'Remove notes.txt' }));
    await waitFor(() => {
      expect(deletedUrls).toEqual(['/api/v1/attachments/att_left_staged']);
    });
  });

  it('encrypts files before upload, sends their keys only sealed, and decrypts them on download', async () => {
    const uploads: { url: string; name: string; type: string; bytes: Uint8Array }[] = [];
    const posted: Record<string, unknown>[] = [];
    const patched: Record<string, unknown>[] = [];
    const saved: Blob[] = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
      saved.push(b as Blob);
      return `blob:test/${saved.length}`;
    });
    // jsdom cannot navigate to a download.
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    let failUploads = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = init?.method ?? 'GET';
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [{ id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '', is_private: false, last_seq: 0, created_by: 'u_alice', created_at: Date.now(), role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all' }],
            attachments: { max_upload_bytes: 10 * 1024 * 1024, max_per_message: 10 },
          });
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/attachments') && method === 'POST') {
          const file = (init?.body as FormData).get('file') as File;
          uploads.push({ url, name: file.name, type: file.type, bytes: new Uint8Array(await file.arrayBuffer()) });
          if (failUploads) return json({ error: 'storage full' }, 500);
          return json({ attachment: { id: `att_enc${uploads.length}`, room_id: 'rm_gen', uploader_id: 'u_alice', filename: 'encrypted.bin', mime_type: 'application/octet-stream', size_bytes: file.size, sha256_hex: '', created_at: 1 } }, 201);
        }
        if (url === '/api/v1/rooms/rm_gen/messages' && method === 'POST') {
          const req = JSON.parse(String(init?.body)) as Record<string, unknown>;
          posted.push(req);
          return json({ message: { id: 'm_file', room_id: 'rm_gen', seq: 1, sender_id: 'u_alice', sender_name: 'Alice', encoding: 'e2ee_room_v1', body: req.body, created_at: Date.now(), reactions: [], attachments: [{ id: 'att_enc1', room_id: 'rm_gen', uploader_id: 'u_alice', filename: 'encrypted.bin', mime_type: 'application/octet-stream', size_bytes: uploads[0].bytes.length, sha256_hex: '', created_at: 1 }] } }, 201);
        }
        if (url === '/api/v1/rooms/rm_gen/messages/m_late' && method === 'PATCH') {
          const req = JSON.parse(String(init?.body)) as Record<string, unknown>;
          patched.push(req);
          // As the server does: the edit replaces the body and the first envelope is kept.
          return json({ message: { ...lateMessage(), body: req.body, original_body: lateMessage().body, edited_at: Date.now() } });
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) return json({ messages: [], has_more: false });
        if (url === '/api/v1/attachments/att_enc1' && method === 'GET') return new Response(uploads[0].bytes);
        return json({ error: 'not found' }, 404);
      }),
    );

    const { container } = render(<Chat />);
    await screen.findByRole('heading', { name: 'Welcome to #general' });
    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [new File(['hello world'], 'report.txt', { type: 'text/plain' })] } });
    await screen.findByText('11 B');

    // The server receives opaque ciphertext under a generic name, never the file's name or type.
    expect(uploads).toHaveLength(1);
    expect(uploads[0]).toMatchObject({ url: '/api/v1/rooms/rm_gen/attachments?encrypted=1', name: 'encrypted.bin', type: 'application/octet-stream' });
    expect(uploads[0].bytes.length).toBe(11 + 16);
    expect(new TextDecoder().decode(uploads[0].bytes)).not.toContain('hello');

    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await screen.findByRole('button', { name: 'Download report.txt' });
    expect(posted).toHaveLength(1);
    expect(posted[0].attachment_ids).toEqual(['att_enc1']);
    // The key, name and type travel only inside the sealed envelope.
    const outside = JSON.stringify({ ...posted[0], body: undefined });
    expect(outside).not.toContain('report.txt');
    expect(outside).not.toContain('"key"');
    const env = JSON.parse(String(posted[0].body)) as { ciphertext: string };
    const inner = JSON.parse(atob(env.ciphertext)) as { type: string; ref: string; files: { name: string; mime_type: string; key: string }[] };
    expect(inner.type).toBe('attachment');
    // The message seals its idempotency key as the ID its edits name.
    expect(inner.ref).toBe(posted[0].idempotency_key);
    expect(inner.files[0]).toMatchObject({ name: 'report.txt', mime_type: 'text/plain' });
    expect(inner.files[0].key).toMatch(/^[A-Za-z0-9+/]{43}$/);
    expect(screen.queryByText('File not encrypted')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Download report.txt' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    // Saved untyped, so the decrypted copy can never render as this origin.
    expect(saved[0].type).toBe('application/octet-stream');
    expect(new TextDecoder().decode(await saved[0].arrayBuffer())).toBe('hello world');

    // A message whose key arrives late still opens with its files. An edit afterwards seals only
    // its text (never the file keys) and the files still open, from the kept first envelope.
    const lateInner = { room_id: 'rm_gen', type: 'attachment' as const, body: 'late note', ref: 'late-ref-0001', files: inner.files };
    const lateMessage = () => ({
      id: 'm_late', room_id: 'rm_gen', seq: 2, sender_id: 'u_alice', sender_name: 'Alice', encoding: 'e2ee_room_v1',
      body: fakeEnvelope(lateInner, 's_late'), created_at: Date.now(), reactions: [],
      attachments: [{ id: 'att_enc1', room_id: 'rm_gen', uploader_id: 'u_alice', filename: 'encrypted.bin', mime_type: 'application/octet-stream', size_bytes: 27, sha256_hex: '', created_at: 1 }],
    });
    act(() => FakeWebSocket.instances[0].emit({ t: 'message.new', room: 'rm_gen', seq: 2, d: lateMessage() }));
    expect(await screen.findByText("Waiting for this message's key")).toBeTruthy();
    act(() => deliverKey('s_late'));
    expect(await screen.findByText('late note')).toBeTruthy();
    expect(screen.getAllByRole('button', { name: 'Download report.txt' })).toHaveLength(2);
    expect(screen.queryByText('File not encrypted')).toBeNull();
    const lateRow = screen.getByText('late note').closest('article') as HTMLElement;
    fireEvent.click(within(lateRow).getByRole('button', { name: 'Edit message' }));
    const editBox = within(lateRow).getByRole('textbox', { name: 'Edit message' });
    fireEvent.change(editBox, { target: { value: 'late note, edited' } });
    fireEvent.keyDown(editBox, { key: 'Enter' });
    await waitFor(() => expect(patched).toHaveLength(1));
    const editInner = JSON.parse(atob((JSON.parse(String(patched[0].body)) as { ciphertext: string }).ciphertext)) as { type: string; files?: unknown[]; original: unknown };
    expect(editInner.type).toBe('edit');
    expect(editInner.files).toBeUndefined();
    expect(editInner.original).toEqual({ kind: 'e5', ref: 'late-ref-0001', files: 1 });
    expect(String(patched[0].body)).not.toContain(inner.files[0].key);
    expect(await screen.findByText('late note, edited')).toBeTruthy();
    expect(screen.getAllByRole('button', { name: 'Download report.txt' })).toHaveLength(2);

    // A refused upload is an error on its chip; there is no plaintext retry.
    failUploads = true;
    fireEvent.change(fileInput, { target: { files: [new File(['again'], 'second.txt', { type: 'text/plain' })] } });
    await screen.findByText('storage full');
    expect(uploads).toHaveLength(2);
    expect(uploads.every((u) => u.url.endsWith('?encrypted=1') && u.name === 'encrypted.bin')).toBe(true);
  });

  it.each([false, true])('refetches a slim edit of seq 1 when its history is still in flight: %s', async (early) => {
    const fetched: string[] = [];
    let releaseHistory = () => {};
    const history = new Promise<void>((resolve) => { releaseHistory = resolve; });
    const row = (body: string, edited?: number) => ({ id: 'm_old', room_id: 'rm_gen', seq: 1, sender_id: 'bot_1', sender_name: 'Bot', encoding: 'plain_v1', body, created_at: 1, reactions: [], attachments: [], ...(edited ? { edited_at: edited } : {}) });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [{ id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '', is_private: false, last_seq: 9, created_by: 'u_alice', created_at: Date.now(), role: 'owner', last_read_seq: 9, unread_count: 0, notify_mode: 'all' }],
          });
        }
        if (url === '/api/v1/rooms/rm_gen/messages/m_old') {
          fetched.push(url);
          // The first read fails (a transient error); the retry gets the edited row.
          return fetched.length === 1 ? json({ error: 'busy' }, 503) : json({ message: row('caption, edited', 50) });
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          if (early) await history;
          return json({ messages: [row('first caption')], has_more: false });
        }
        return json({ error: 'not found' }, 404);
      }),
    );
    render(<Chat />);
    if (early) await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    else await screen.findByText('first caption');
    act(() => FakeWebSocket.instances[0].emit({ t: 'message.edit', room: 'rm_gen', seq: 1, d: { refetch: true, id: 'm_old' } }));
    releaseHistory();
    expect(await screen.findByText('caption, edited', {}, { timeout: 3000 })).toBeTruthy();
    expect(fetched).toEqual(['/api/v1/rooms/rm_gen/messages/m_old', '/api/v1/rooms/rm_gen/messages/m_old']);
  });

  it.each(['ref', 'sender', 'room'])('rejects send confirmation with a different %s', async (mismatch) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [{ id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '', is_private: false, last_seq: 0, created_by: 'u_alice', created_at: Date.now(), role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all' }],
          });
        }
        if (url === '/api/v1/rooms/rm_gen/messages' && init?.method === 'POST') {
          const ref = mismatch === 'ref' ? 'not-this-send' : new Headers(init.headers).get('Idempotency-Key') ?? '';
          const room_id = mismatch === 'room' ? 'rm_other' : 'rm_gen';
          const sender_id = mismatch === 'sender' ? 'u_other' : 'u_alice';
          return json({ message: { id: 'm_other', room_id, seq: 7, sender_id, sender_name: 'Other', encoding: 'e2ee_room_v1', created_at: 1, reactions: [], attachments: [],
            body: fakeEnvelope({ room_id, type: 'text', body: 'an unrelated message', ref, files: [] }) } }, 201);
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) return json({ messages: [], has_more: false });
        return json({ error: 'not found' }, 404);
      }),
    );
    render(<Chat />);
    await screen.findByRole('heading', { name: 'Welcome to #general' });
    fireEvent.change(screen.getByLabelText('Message input'), { target: { value: 'hello there' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    expect(await screen.findByText(/The server did not confirm this message|Unexpected message/)).toBeTruthy();
    expect(screen.getByText('hello there')).toBeTruthy();
    expect(screen.queryByText('an unrelated message')).toBeNull();
  });

  it('closes an image preview when its message is deleted', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return json({
            user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
            tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
            rooms: [{ id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '', is_private: false, last_seq: 1, created_by: 'u_alice', created_at: Date.now(), role: 'owner', last_read_seq: 1, unread_count: 0, notify_mode: 'all' }],
          });
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return json({ messages: [{ id: 'm_img', room_id: 'rm_gen', seq: 1, sender_id: 'bot_1', sender_name: 'Bot', encoding: 'plain_v1', body: '', created_at: Date.now(), reactions: [],
            attachments: [{ id: 'att_png', room_id: 'rm_gen', uploader_id: 'bot_1', filename: 'chart.png', mime_type: 'image/png', size_bytes: 10, sha256_hex: '', created_at: 1 }] }], has_more: false });
        }
        return json({ error: 'not found' }, 404);
      }),
    );
    render(<Chat />);
    fireEvent.click(await screen.findByRole('button', { name: 'Preview chart.png' }));
    expect(screen.getByRole('dialog', { name: 'Image preview: chart.png' })).toBeTruthy();
    act(() => FakeWebSocket.instances[0].emit({ t: 'message.delete', room: 'rm_gen', seq: 2, d: { id: 'm_img', deleted_at: Date.now() } }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Image preview: chart.png' })).toBeNull());
  });

  it('hides the attachment button when bootstrap reports attachments.available=false', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return Promise.resolve(
            json({
              user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
              tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
              rooms: [
                {
                  id: 'rm_gen',
                  tenant_id: 'default',
                  kind: 'channel',
                  name: 'general',
                  topic: '',
                  is_private: false,
                  last_seq: 0,
                  created_by: 'u_alice',
                  created_at: Date.now(),
                  role: 'owner',
                  last_read_seq: 0,
                  unread_count: 0,
                  notify_mode: 'all',
                },
              ],
              attachments: { available: false, max_upload_bytes: 10 * 1024 * 1024, max_per_message: 10 },
            }),
          );
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return Promise.resolve(json({ messages: [], has_more: false }));
        }
        return Promise.resolve(json({ error: 'not found' }, 404));
      }),
    );

    render(<Chat />);
    await screen.findByRole('heading', { name: 'Welcome to #general' });
    expect(screen.queryByRole('button', { name: 'Attach files' })).toBeNull();
  });

  it('falls back to the first room when the #room= hash has a malformed percent-escape', async () => {
    window.history.replaceState(null, '', '/#room=%E0');
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return Promise.resolve(
            json({
              user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
              tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
              rooms: [
                {
                  id: 'rm_gen',
                  tenant_id: 'default',
                  kind: 'channel',
                  name: 'general',
                  topic: '',
                  is_private: false,
                  last_seq: 0,
                  created_by: 'u_alice',
                  created_at: Date.now(),
                  role: 'owner',
                  last_read_seq: 0,
                  unread_count: 0,
                  notify_mode: 'all',
                },
                {
                  id: 'rm_rand',
                  tenant_id: 'default',
                  kind: 'channel',
                  name: 'random',
                  topic: '',
                  is_private: false,
                  last_seq: 0,
                  created_by: 'u_alice',
                  created_at: Date.now(),
                  role: 'member',
                  last_read_seq: 0,
                  unread_count: 0,
                  notify_mode: 'all',
                },
              ],
            }),
          );
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return Promise.resolve(json({ messages: [], has_more: false }));
        }
        return Promise.resolve(json({ error: 'not found' }, 404));
      }),
    );

    render(<Chat />);
    await screen.findByRole('heading', { name: 'Welcome to #general' });
    // The hash is written by an effect after the room renders.
    await waitFor(() => expect(window.location.hash).toBe('#room=rm_gen'));
  });

  it('keeps a call roster received while joining instead of the older join response', async () => {
    let finishStart = () => {};
    const start = vi.spyOn(HybridCallController.prototype, 'start').mockImplementation(
      () => new Promise<void>((resolve) => { finishStart = resolve; }),
    );
    const alice = { user_id: 'u_alice', display_name: 'Alice' };
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url === '/api/v1/bootstrap') {
          return Promise.resolve(
            json({
              user: { id: 'u_alice', username: 'alice', display_name: 'Alice', role: 'user' },
              tenant: { id: 'default', slug: 'default', display_name: 'Busnes HQ', plan: 'self_hosted' },
              rooms: [
                {
                  id: 'rm_gen', tenant_id: 'default', kind: 'channel', name: 'general', topic: '',
                  is_private: false, last_seq: 0, created_by: 'u_alice', created_at: Date.now(),
                  role: 'owner', last_read_seq: 0, unread_count: 0, notify_mode: 'all',
                },
              ],
            }),
          );
        }
        if (url.startsWith('/api/v1/rooms/rm_gen/messages')) {
          return Promise.resolve(json({ messages: [], has_more: false }));
        }
        if (url === '/api/v1/rooms/rm_gen/calls/join') {
          return Promise.resolve(json({ call_id: 'c1', room_id: 'rm_gen', mode: 'p2p_mesh', epoch: 1, peers: [alice] }));
        }
        return Promise.resolve(json({ error: 'not found' }, 404));
      }),
    );

    try {
      render(<Chat />);
      await screen.findByRole('heading', { name: 'Welcome to #general' });
      fireEvent.click(screen.getByRole('button', { name: 'Audio call' }));
      await waitFor(() => expect(start).toHaveBeenCalled());

      act(() => {
        FakeWebSocket.instances[0].emit({
          t: 'call.state',
          room: 'rm_gen',
          d: {
            call_id: 'c1', room_id: 'rm_gen', active: true, mode: 'p2p_mesh', epoch: 2,
            peers: [alice, { user_id: 'u_bob', display_name: 'Bob' }, { user_id: 'u_carol', display_name: 'Carol' }],
          },
        });
      });
      await screen.findByTitle('3 in active call');

      await act(async () => finishStart());
      expect(screen.getByTitle('3 in active call')).toBeTruthy();
      expect(screen.queryByTitle('1 in active call')).toBeNull();
    } finally {
      start.mockRestore();
    }
  });
});
