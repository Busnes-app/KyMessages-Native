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
});
