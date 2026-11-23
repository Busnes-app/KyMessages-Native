import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MessageRow } from './MessageRow';
import type { ChatMessage } from '../../chat/types';

afterEach(cleanup);

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
  });
});
