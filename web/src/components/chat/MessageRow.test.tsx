import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MessageRow } from './MessageRow';
import type { ChatAttachment, ChatMessage } from '../../chat/types';
import { encryptBlob, type FileDescriptor } from '../../crypto/attachments';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const baseMsg: ChatMessage = {
  id: 'm1',
  tenant_id: 't1',
  room_id: 'r1',
  seq: 12,
  sender_id: 'u1',
  sender_name: 'Alice',
  encoding: 'plain_v1',
  body: 'See https://example.com/docs and `code`',
  created_at: 1_700_000_000_000,
  reactions: [],
  attachments: [],
  delivery: { kind: 'synced' },
};

const replyMsg: ChatMessage = {
  ...baseMsg,
  id: 'm0',
  seq: 11,
  body: 'Original message',
};

describe('MessageRow', () => {
  it('marks a webhook post that borrows a member name', () => {
    render(
      <MessageRow
        message={{ ...baseMsg, sender_id: 'webhook:wh_1', sender_name: 'Alice' }}
        grouped={false}
        currentUserId="u_bob"
        canModerate={false}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );
    expect(screen.getByText('Webhook')).toBeTruthy();
  });

  it('marks a native bot post with a Bot badge', () => {
    render(
      <MessageRow
        message={{ ...baseMsg, sender_id: 'bot_123', sender_name: 'Triage Bot' }}
        grouped={false}
        currentUserId="u_bob"
        canModerate={false}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );
    expect(screen.getByText('Bot')).toBeTruthy();
  });

  it('shows no badge on a member post', () => {
    render(
      <MessageRow
        message={baseMsg}
        grouped={false}
        currentUserId="u_bob"
        canModerate={false}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );
    expect(screen.queryByText('Webhook')).toBeNull();
    expect(screen.queryByText('Bot')).toBeNull();
  });

  it('renders formatted links with chat-inline-link and jumpable replies with is-clickable', () => {
    const onJump = vi.fn();
    const { container } = render(
      <MessageRow
        message={{ ...baseMsg, reply_to_id: 'm0' }}
        grouped={false}
        currentUserId="u1"
        canModerate={false}
        replyTarget={replyMsg}
        onReply={vi.fn()}
        onJumpToMessage={onJump}
        onToggleReaction={vi.fn()}
        onEdit={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );

    const link = container.querySelector('a.chat-inline-link');
    expect(link?.getAttribute('href')).toBe('https://example.com/docs');

    const quote = container.querySelector('button.chat-reply-quote.is-clickable');
    expect(quote).toBeTruthy();
    fireEvent.click(quote!);
    expect(onJump).toHaveBeenCalledWith(11);
  });

  it('does not reopen the editor after saving an ArrowUp-triggered edit and surfaces edit errors', async () => {
    const onEdit = vi.fn().mockResolvedValue(undefined);
    const onConsumed = vi.fn();
    const { rerender } = render(
      <MessageRow
        message={baseMsg}
        grouped={false}
        currentUserId="u1"
        canModerate={false}
        editTrigger={1001}
        onEditTriggerConsumed={onConsumed}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={onEdit}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );

    expect(onConsumed).toHaveBeenCalledTimes(1);
    const editor = screen.getByRole('textbox', { name: 'Edit message' }) as HTMLTextAreaElement;
    fireEvent.change(editor, { target: { value: 'Updated text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(onEdit).toHaveBeenCalledWith('m1', 'Updated text'));
    // Simulate parent updating message.body even while editTrigger prop is still the same value
    rerender(
      <MessageRow
        message={{ ...baseMsg, body: 'Updated text', edited_at: Date.now() }}
        grouped={false}
        currentUserId="u1"
        canModerate={false}
        editTrigger={1001}
        onEditTriggerConsumed={onConsumed}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={onEdit}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );
    expect(screen.queryByRole('textbox', { name: 'Edit message' })).toBeNull();

    // Failed edit displays inline error alert
    const failingEdit = vi.fn().mockRejectedValue(new Error('Network offline'));
    rerender(
      <MessageRow
        message={{ ...baseMsg, body: 'Updated text' }}
        grouped={false}
        currentUserId="u1"
        canModerate={false}
        editTrigger={1002}
        onReply={vi.fn()}
        onToggleReaction={vi.fn()}
        onEdit={failingEdit}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );
    const editor2 = screen.getByRole('textbox', { name: 'Edit message' }) as HTMLTextAreaElement;
    fireEvent.change(editor2, { target: { value: 'Another edit' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Network offline');
  });

  it('renders inline raster images with preview trigger and non-image files as download links', () => {
    const onPreview = vi.fn();
    const imgAtt = {
      id: 'att_img1',
      tenant_id: 't1',
      room_id: 'r1',
      message_id: 'm1',
      uploader_id: 'u1',
      filename: 'diagram.png',
      mime_type: 'image/png',
      size_bytes: 2048,
      sha256_hex: 'deadbeef',
      created_at: 1_700_000_000_000,
    };
    const fileAtt = {
      id: 'att_file1',
      tenant_id: 't1',
      room_id: 'r1',
      message_id: 'm1',
      uploader_id: 'u1',
      filename: 'notes.txt',
      mime_type: 'application/octet-stream',
      size_bytes: 512,
      sha256_hex: 'cafebabe',
      created_at: 1_700_000_000_000,
    };

    render(
      <MessageRow
        message={{ ...baseMsg, body: '', attachments: [imgAtt, fileAtt] }}
        grouped={false}
        currentUserId="u1"
        canModerate={false}
        onReply={vi.fn()}
        onPreviewImage={onPreview}
        onToggleReaction={vi.fn()}
        onEdit={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onRetryFailed={vi.fn()}
        onDismissFailed={vi.fn()}
      />,
    );

    const img = screen.getByRole('img', { name: 'diagram.png' });
    expect(img.getAttribute('src')).toBe('/api/v1/attachments/att_img1?inline=1');

    fireEvent.click(screen.getByRole('button', { name: 'Preview diagram.png' }));
    expect(onPreview).toHaveBeenCalledWith(imgAtt);

    const fileLink = screen.getByRole('link', { name: /notes\.txt/i });
    expect(fileLink.getAttribute('href')).toBe('/api/v1/attachments/att_file1');
    expect(fileLink.getAttribute('download')).toBe('notes.txt');
  });

  describe('encryption labels', () => {
    const row = (message: ChatMessage, currentUserId = 'u_bob') =>
      render(
        <MessageRow
          message={message}
          grouped={false}
          currentUserId={currentUserId}
          canModerate={false}
          onReply={vi.fn()}
          onToggleReaction={vi.fn()}
          onEdit={vi.fn().mockResolvedValue(undefined)}
          onDelete={vi.fn().mockResolvedValue(undefined)}
          onRetryFailed={vi.fn()}
          onDismissFailed={vi.fn()}
        />,
      );
    const sealed: ChatMessage = { ...baseMsg, encoding: 'e2ee_room_v1', body: 'Ship it', envelope: '{}', e2ee: { kind: 'decrypted' } };

    it('says plaintext from a person was sent before encryption, and from a bot that it is not encrypted', () => {
      row(baseMsg);
      expect(screen.getByText('Sent before encryption')).toBeTruthy();
      cleanup();
      row({ ...baseMsg, sender_id: 'bot_1', sender_name: 'Triage Bot' });
      expect(screen.getByText('Not encrypted (bot)')).toBeTruthy();
      expect(screen.queryByText('Sent before encryption')).toBeNull();
      cleanup();
      row({ ...baseMsg, sender_id: 'webhook:wh_1', sender_name: 'CI' });
      expect(screen.getByText('Not encrypted (webhook)')).toBeTruthy();
    });

    it('shows a decrypted message without a label, but marks its files as not encrypted', () => {
      row(sealed);
      expect(screen.getByText('Ship it')).toBeTruthy();
      expect(screen.queryByText('Sent before encryption')).toBeNull();
      expect(screen.queryByText('File not encrypted')).toBeNull();
      cleanup();
      row({
        ...sealed,
        attachments: [{ id: 'att_1', tenant_id: 't1', room_id: 'r1', uploader_id: 'u1', filename: 'plan.pdf', mime_type: 'application/pdf', size_bytes: 10, sha256_hex: '', created_at: 1 }],
      });
      expect(screen.getByText('File not encrypted')).toBeTruthy();
    });

    it('says when a message waits for its key or cannot be decrypted, and offers no edit', () => {
      row({ ...sealed, body: '', e2ee: { kind: 'waiting' } }, 'u1');
      expect(screen.getByText("Waiting for this message's key")).toBeTruthy();
      expect(screen.queryByRole('button', { name: /edit/i })).toBeNull();
      cleanup();
      row({ ...sealed, body: '', e2ee: { kind: 'failed', reason: 'This message was encrypted for another room.' } });
      expect(screen.getByText("Can't decrypt this message. This message was encrypted for another room.")).toBeTruthy();
    });

    const att = (id: string): ChatAttachment => ({ id, tenant_id: 't1', room_id: 'r1', uploader_id: 'u1', filename: 'encrypted.bin', mime_type: 'application/octet-stream', size_bytes: 10, sha256_hex: '', created_at: 1 });

    it('names encrypted files by their decrypted names and never offers an upload the message does not name', () => {
      const file = { attachment_id: 'att_sealed', name: 'budget.xlsx', size: 2048 } as FileDescriptor;
      row({ ...sealed, body: '', files: [file], attachments: [att('att_sealed'), { ...att('att_old'), filename: 'old.pdf' }] });
      expect(screen.getByRole('button', { name: 'Download budget.xlsx' })).toBeTruthy();
      expect(screen.queryByText('encrypted.bin')).toBeNull();
      // A server-added upload in a message that names its files is hidden, never "not encrypted".
      expect(screen.queryByText('File not encrypted')).toBeNull();
      expect(screen.queryByRole('link')).toBeNull();
      expect(screen.getByRole('note').textContent).toMatch(/An attachment this message does not include was hidden/);
    });

    it('shows a named file the server did not attach as unavailable', () => {
      const file = { attachment_id: 'att_gone', name: 'budget.xlsx', size: 2048, missing: true } as FileDescriptor & { missing: true };
      row({ ...sealed, body: 'see file', files: [file], attachments: [] });
      expect(screen.getByText('budget.xlsx')).toBeTruthy();
      expect(screen.getByText('Attachment unavailable')).toBeTruthy();
      expect(screen.queryByRole('button', { name: /Download/ })).toBeNull();
    });

    it('shows the uploads of a message whose files cannot be read here as unavailable, not plaintext', () => {
      row({ ...sealed, body: 'new caption', filesState: { reason: 'This message was sent before this device could read the room.' }, attachments: [att('att_1')] });
      expect(screen.getByText(/Attachment unavailable\. This message was sent before this device could read the room\./)).toBeTruthy();
      expect(screen.queryByText('File not encrypted')).toBeNull();
      expect(screen.queryByRole('link')).toBeNull();
    });

    it('labels the uploads of a message from before E5 as not encrypted', () => {
      row({ ...sealed, body: 'old', attachments: [{ ...att('att_old'), filename: 'old.pdf' }] });
      expect(screen.getByText('File not encrypted')).toBeTruthy();
      expect(screen.getByRole('link', { name: /old\.pdf/ }).getAttribute('href')).toBe('/api/v1/attachments/att_old');
    });

    it('never calls the uploads of an unopened encrypted message plaintext', () => {
      row({ ...sealed, body: '', e2ee: { kind: 'waiting' }, attachments: [att('att_x')] });
      expect(screen.queryByText('File not encrypted')).toBeNull();
      expect(screen.queryByRole('link')).toBeNull();
    });

    // A PNG header (signature and IHDR) declaring width x height.
    const pngHeader = (width: number, height: number) => {
      const b = new Uint8Array(33);
      b.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
      new DataView(b.buffer).setUint32(16, width);
      new DataView(b.buffer).setUint32(20, height);
      return b;
    };

    it('never decodes a thumbnail whose header declares another size, such as a decompression bomb', async () => {
      for (const [w, h, why] of [[30000, 30000, /too large/], [5, 3, /not the size/]] as const) {
        const { ciphertext, sealed: t } = await encryptBlob(new Blob([pngHeader(w, h)]), 'thumb');
        const thumb = { ...t, attachment_id: 'att_thumb', mime_type: 'image/png', width: 4, height: 3 };
        vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext)));
        const made = vi.spyOn(URL, 'createObjectURL');
        row({ ...sealed, body: '', files: [{ attachment_id: 'att_img', name: 'photo.png', mime_type: 'image/png', size: 9, thumb } as FileDescriptor], attachments: [att('att_img'), att('att_thumb')] });
        expect(await screen.findByText(why)).toBeTruthy();
        expect(screen.queryByRole('img')).toBeNull();
        expect(made).not.toHaveBeenCalled();
        cleanup();
      }
    });

    it('decrypts a thumbnail into a blob: URL and revokes it on unmount', async () => {
      const png = pngHeader(4, 3);
      const { ciphertext, sealed: t } = await encryptBlob(new Blob([png]), 'thumb');
      const thumb = { ...t, attachment_id: 'att_thumb', mime_type: 'image/png', width: 4, height: 3 };
      const file = { attachment_id: 'att_img', name: 'photo.png', mime_type: 'image/png', size: 9000, thumb } as FileDescriptor;
      const fetched: string[] = [];
      vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        fetched.push(url);
        return new Response(ciphertext);
      }));
      const made: Blob[] = [];
      vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => {
        made.push(b as Blob);
        return 'blob:thumb';
      });
      const revoke = vi.spyOn(URL, 'revokeObjectURL');
      const onPreviewFile = vi.fn();
      const { unmount } = render(
        <MessageRow
          message={{ ...sealed, body: '', files: [file], attachments: [att('att_img'), att('att_thumb')] }}
          grouped={false}
          currentUserId="u_bob"
          canModerate={false}
          onReply={vi.fn()}
          onPreviewFile={onPreviewFile}
          onToggleReaction={vi.fn()}
          onEdit={vi.fn().mockResolvedValue(undefined)}
          onDelete={vi.fn().mockResolvedValue(undefined)}
          onRetryFailed={vi.fn()}
          onDismissFailed={vi.fn()}
        />,
      );
      const img = await screen.findByRole('img', { name: 'photo.png' });
      expect(img.getAttribute('src')).toBe('blob:thumb');
      // Only the thumbnail is fetched; the full image waits for a preview or download.
      expect(fetched).toEqual(['/api/v1/attachments/att_thumb']);
      expect(made[0].type).toBe('image/png');
      expect(new Uint8Array(await made[0].arrayBuffer())).toEqual(png);
      expect(screen.queryByText('File not encrypted')).toBeNull();
      fireEvent.click(screen.getByRole('button', { name: 'Preview photo.png' }));
      expect(onPreviewFile).toHaveBeenCalledWith(file);
      unmount();
      expect(revoke).toHaveBeenCalledWith('blob:thumb');
    });

    it('abandons a download and makes no decrypted copy when the row goes away', async () => {
      let sawSignal: AbortSignal | undefined;
      vi.stubGlobal('fetch', vi.fn((_url: string, init?: RequestInit) => {
        sawSignal = init?.signal ?? undefined;
        return new Promise<Response>(() => undefined);
      }));
      const made = vi.spyOn(URL, 'createObjectURL');
      const file = { attachment_id: 'att_sealed', v: 1, alg: 'A256GCM-STREAM', key: 'A'.repeat(43), nonce_prefix: 'A'.repeat(10), chunk_size: 65536, sha256: 'a'.repeat(64), ciphertext_size: 26, size: 10, name: 'budget.xlsx', mime_type: 'application/vnd.ms-excel' } as FileDescriptor;
      const { unmount } = row({ ...sealed, body: '', files: [file], attachments: [att('att_sealed')] });
      fireEvent.click(screen.getByRole('button', { name: 'Download budget.xlsx' }));
      await waitFor(() => expect(sawSignal).toBeDefined());
      expect(sawSignal!.aborted).toBe(false);
      unmount();
      expect(sawSignal!.aborted).toBe(true);
      expect(made).not.toHaveBeenCalled();
    });

    it('shows a tampered thumbnail as an error, never as an image', async () => {
      const { ciphertext, sealed: t } = await encryptBlob(new Blob([new Uint8Array(5)]), 'thumb');
      ciphertext[0] ^= 1;
      const thumb = { ...t, attachment_id: 'att_thumb', mime_type: 'image/png', width: 4, height: 3 };
      vi.stubGlobal('fetch', vi.fn(async () => new Response(ciphertext)));
      const made = vi.spyOn(URL, 'createObjectURL');
      row({ ...sealed, body: '', files: [{ attachment_id: 'att_img', name: 'photo.png', mime_type: 'image/png', size: 9, thumb } as FileDescriptor], attachments: [att('att_img'), att('att_thumb')] });
      expect(await screen.findByText(/damaged or was changed/)).toBeTruthy();
      expect(screen.queryByRole('img')).toBeNull();
      expect(made).not.toHaveBeenCalled();
    });
  });
});
