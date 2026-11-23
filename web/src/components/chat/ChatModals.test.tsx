import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ChatDirectoryUser, ChatMessage, ChatRoomSummary } from '../../chat/types';

const searchMessages = vi.fn();
const searchIndexFor = vi.fn();
vi.mock('../../chat/searchIndex', () => ({ searchIndexFor: (userId: string) => searchIndexFor(userId) }));

const { CreateChannelModal, SearchModal, StartDMModal } = await import('./ChatModals');

afterEach(() => {
  cleanup();
  searchMessages.mockReset();
});

const user = (id: string, username: string, display_name: string): ChatDirectoryUser => ({ id, username, display_name, role: 'user' });
const directory = [user('me', 'admin', 'Administrator'), user('u1', 'ana', 'Ana Lima'), user('u2', 'ben', 'Ben Okafor'), user('u3', 'chen', 'Chen Wu')];

// Opener renders a button that opens the modal and closes it on onClose, as Chat.tsx does.
function Opener({ modal }: { modal: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>Open</button>
      {open && modal(() => setOpen(false))}
    </>
  );
}

function activeOption(box: HTMLElement): string | null {
  const id = box.getAttribute('aria-activedescendant');
  return id ? document.getElementById(id)?.textContent ?? null : null;
}

describe('ChatDialog', () => {
  it('focuses the autoFocus field, closes on Escape and returns focus to the opener', async () => {
    render(<Opener modal={(close) => <CreateChannelModal directory={directory} currentUserId="me" onClose={close} onCreate={async () => {}} />} />);
    const opener = screen.getByRole('button', { name: 'Open' });
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByRole('dialog', { name: 'Create channel' });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByLabelText('Channel name')));
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
    await waitFor(() => expect(dialog.isConnected).toBe(false));
    await waitFor(() => expect(document.activeElement).toBe(opener));
  });

  it('closes on Escape from inside a picker box', async () => {
    const onClose = vi.fn();
    render(<StartDMModal directory={directory} currentUserId="me" onClose={onClose} onSelectUser={async () => {}} />);
    const box = await screen.findByRole('combobox', { name: 'Filter teammates' });
    await waitFor(() => expect(document.activeElement).toBe(box));
    fireEvent.change(box, { target: { value: 'an' } });
    fireEvent.keyDown(box, { key: 'Escape' });
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });
});

describe('CreateChannelModal', () => {
  it('picks several teammates by keyboard from the search box and sends them', async () => {
    const onCreate = vi.fn(async () => {});
    render(<CreateChannelModal directory={directory} currentUserId="me" onClose={() => {}} onCreate={onCreate} />);
    fireEvent.change(await screen.findByLabelText('Channel name'), { target: { value: 'launch' } });
    const box = screen.getByRole('combobox', { name: 'Add teammates' });
    const list = screen.getByRole('listbox', { name: 'Teammates' });
    expect(list.getAttribute('aria-multiselectable')).toBe('true');
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual(['Ana Lima @ana', 'Ben Okafor @ben', 'Chen Wu @chen']);

    box.focus();
    // The arrows move through the teammates from the box; Enter adds the highlighted one.
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    await waitFor(() => expect(activeOption(box)).toBe('Ana Lima @ana'));
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    await waitFor(() => expect(activeOption(box)).toBe('Ben Okafor @ben'));
    fireEvent.keyDown(box, { key: 'Enter' });
    await waitFor(() => expect(screen.getByRole('option', { name: /Ben Okafor/ }).getAttribute('aria-selected')).toBe('true'));

    // Typing narrows the list; the arrows reach the match and Enter adds it too.
    fireEvent.change(box, { target: { value: 'chen' } });
    await waitFor(() => expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual(['Chen Wu @chen']));
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    await waitFor(() => expect(activeOption(box)).toBe('Chen Wu @chen'));
    fireEvent.keyDown(box, { key: 'Enter' });
    await waitFor(() => expect(screen.getByRole('option', { name: /Chen Wu/ }).getAttribute('aria-selected')).toBe('true'));
    expect(onCreate).not.toHaveBeenCalled();

    // A click toggles too.
    fireEvent.change(box, { target: { value: '' } });
    fireEvent.click(await screen.findByRole('option', { name: /Ben Okafor/ }));
    await waitFor(() => expect(screen.getByRole('option', { name: /Ben Okafor/ }).getAttribute('aria-selected')).toBe('false'));

    fireEvent.click(screen.getByRole('button', { name: 'Create channel' }));
    await waitFor(() => expect(onCreate).toHaveBeenCalledWith({ name: 'launch', topic: '', isPrivate: false, memberIds: ['u3'] }));
  });
});

describe('StartDMModal', () => {
  it('moves through teammates with the arrows from the box and Enter opens one', async () => {
    const onSelectUser = vi.fn(async () => {});
    const onClose = vi.fn();
    render(<StartDMModal directory={directory} currentUserId="me" onClose={onClose} onSelectUser={onSelectUser} />);
    const box = await screen.findByRole('combobox', { name: 'Filter teammates' });
    expect(screen.getByRole('listbox', { name: 'Teammates' })).toBeTruthy();
    // The first teammate is highlighted from the start, as before.
    await waitFor(() => expect(activeOption(box)).toBe('Ana Lima@ana'));
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    await waitFor(() => expect(activeOption(box)).toBe('Ben Okafor@ben'));
    fireEvent.keyDown(box, { key: 'ArrowUp' });
    fireEvent.keyDown(box, { key: 'ArrowUp' });
    await waitFor(() => expect(activeOption(box)).toBe('Chen Wu@chen'));
    fireEvent.keyDown(box, { key: 'Enter' });
    await waitFor(() => expect(onSelectUser).toHaveBeenCalledWith('u3'));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it('filters by name or username and says when nothing matches', async () => {
    const onSelectUser = vi.fn(async () => {});
    render(<StartDMModal directory={directory} currentUserId="me" onClose={() => {}} onSelectUser={onSelectUser} />);
    const box = await screen.findByRole('combobox', { name: 'Filter teammates' });
    fireEvent.change(box, { target: { value: 'BEN' } });
    await waitFor(() => expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual(['Ben Okafor@ben']));
    expect((box as HTMLInputElement).value).toBe('BEN');
    fireEvent.change(box, { target: { value: 'zzz' } });
    expect(await screen.findByText('No matching teammates.')).toBeTruthy();
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(onSelectUser).not.toHaveBeenCalled();
  });
});

describe('SearchModal', () => {
  const rooms = [{ id: 'r1', name: 'release-notes', kind: 'channel', is_private: false }] as ChatRoomSummary[];
  const hit = (id: string, seq: number, body: string) =>
    ({ id, seq, body, tenant_id: 't', room_id: 'r1', sender_id: 'me', sender_name: 'Administrator', encoding: 'plain_v1', created_at: 1795334400000, reactions: [], attachments: [], delivery: { kind: 'synced' } }) satisfies ChatMessage;

  it('moves through results with the arrows from the box and Enter opens one', async () => {
    searchMessages.mockResolvedValue([hit('m1', 4, 'Budget review moves'), hit('m2', 7, 'Check the budget sheet')]);
    const onSelectHit = vi.fn();
    const onClose = vi.fn();
    searchIndexFor.mockResolvedValue({ search: searchMessages });
    render(<SearchModal userId="me" rooms={rooms} activeRoomId="r1" onClose={onClose} onSelectHit={onSelectHit} />);
    const box = await screen.findByRole('combobox', { name: 'Search messages' });
    await waitFor(() => expect(document.activeElement).toBe(box));
    fireEvent.change(box, { target: { value: 'budget' } });
    await act(() => new Promise((r) => setTimeout(r, 300)));
    expect(searchIndexFor).toHaveBeenCalledWith('me');
    expect(searchMessages).toHaveBeenCalledWith('budget', undefined);
    expect(await screen.findAllByRole('option')).toHaveLength(2);
    expect(screen.getByRole('listbox', { name: 'Search results' })).toBeTruthy();
    await waitFor(() => expect(activeOption(box)).toMatch(/Budget review moves/));
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    await waitFor(() => expect(activeOption(box)).toMatch(/Check the budget sheet/));
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(onSelectHit).toHaveBeenCalledWith('r1', 7);
    expect(onClose).toHaveBeenCalled();
    // Picking a result never rewrites the query with the result's text.
    expect((box as HTMLInputElement).value).toBe('budget');
  });
});
