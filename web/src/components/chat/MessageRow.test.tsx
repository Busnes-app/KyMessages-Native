import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import type { ChatMessage } from '../../chat/types';
import { MessageRow } from './MessageRow';

afterEach(cleanup);

const noop = () => {};
const base: ChatMessage = {
  id: 'msg_1',
  tenant_id: 'default',
  room_id: 'rm_1',
  seq: 1,
  sender_id: 'u_alice',
  sender_name: 'Alice',
  encoding: 'plain_v1',
  body: 'hello',
  created_at: 1_700_000_000_000,
  reactions: [],
  delivery: { kind: 'synced' },
};

function row(message: ChatMessage) {
  return render(
    <MessageRow
      message={message}
      grouped={false}
      currentUserId="u_bob"
      canModerate={false}
      onReply={noop}
      onToggleReaction={noop}
      onEdit={async () => {}}
      onDelete={async () => {}}
      onRetryFailed={noop}
      onDismissFailed={noop}
    />,
  );
}

it('marks a webhook post that borrows a member name', () => {
  row({ ...base, sender_id: 'webhook:wh_1', sender_name: 'Alice' });
  expect(screen.getByText('Webhook')).toBeTruthy();
});

it('shows no badge on a member post', () => {
  row(base);
  expect(screen.queryByText('Webhook')).toBeNull();
});
