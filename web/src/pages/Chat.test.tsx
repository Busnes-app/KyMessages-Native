import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Chat } from './Chat';
import { deliverKey, fakeEnvelope, resetFakeE2EE, setFakeUnavailable } from '../chat/e2eeFake';

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
        if (url === '/api/v1/rooms/rm_gen/attachments' && method === 'POST') {
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
    expect(uploadSignal?.aborted).toBe(false);

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
});
