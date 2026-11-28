import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BotDevices } from './BotDevices';
import { fakeBots } from '../../chat/e2eeFake';

vi.mock('../../chat/e2ee', () => import('../../chat/e2eeFake'));

const dev = (id: string, code: string) => ({ device_id: id, curve25519: 'c'.repeat(43), ed25519: 'e'.repeat(43), code });
const keys = ({ device_id, curve25519, ed25519 }: ReturnType<typeof dev>) => ({ device_id, curve25519, ed25519 });
const ids = () => fakeBots.vouched.map((d) => d.device_id);

beforeEach(() => {
  fakeBots.bots = [{ user_id: 'bot_helper', username: 'agent-helper', display_name: 'Helper' }];
  fakeBots.uploaded = [dev('BOTDEVICE1', 'ab12-cd34-ef56-0011-2233'), dev('BOTDEVICE2', '9999-8888-7777-6666-5555')];
  fakeBots.vouched = [];
  fakeBots.epoch = 0;
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('BotDevices', () => {
  it('vouches for a device only once the typed code matches, and removes it again', async () => {
    render(<BotDevices onClose={() => undefined} />);
    const inputs = await screen.findAllByLabelText('Code your bot shows');
    const [vouch1] = screen.getAllByRole('button', { name: 'Vouch for this device' });
    expect((vouch1 as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(inputs[0], { target: { value: 'AB12 CD34 EF56 0011 2234' } });
    expect((vouch1 as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole('alert').textContent).toMatch(/The codes differ/);
    fireEvent.change(inputs[0], { target: { value: 'AB12CD34EF5600112233' } });
    expect((vouch1 as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(vouch1);
    await waitFor(() => expect(ids()).toEqual(['BOTDEVICE1']));
    expect(await screen.findByText(/^Vouched for/)).toBeTruthy();
    // Vouching for the second keeps the first; removing it signs a list without it.
    const [input2] = await screen.findAllByLabelText('Code your bot shows');
    fireEvent.change(input2, { target: { value: '9999-8888-7777-6666-5555' } });
    fireEvent.click(screen.getByRole('button', { name: 'Vouch for this device' }));
    await waitFor(() => expect(ids()).toEqual(['BOTDEVICE1', 'BOTDEVICE2']));
    fireEvent.click((await screen.findAllByRole('button', { name: 'Remove' }))[0]);
    await waitFor(() => expect(ids()).toEqual(['BOTDEVICE2']));
  });

  it('reloads the list after a conflict and vouches on the retry, never by itself', async () => {
    render(<BotDevices onClose={() => undefined} />);
    const [input1] = await screen.findAllByLabelText('Code your bot shows');
    // Another tab vouches for BOTDEVICE2 behind this dialog's back.
    fakeBots.vouched = [keys(fakeBots.uploaded[1])];
    fakeBots.epoch = 1;
    fireEvent.change(input1, { target: { value: 'ab12-cd34-ef56-0011-2233' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Vouch for this device' })[0]);
    expect((await screen.findByRole('alert')).textContent).toMatch(/up to date: check it and try again/);
    // The refreshed list is shown and nothing was retried without the user.
    expect(await screen.findByRole('button', { name: 'Remove' })).toBeTruthy();
    expect(ids()).toEqual(['BOTDEVICE2']);
    expect(fakeBots.epoch).toBe(1);
    fireEvent.click(screen.getByRole('button', { name: 'Vouch for this device' }));
    await waitFor(() => expect(ids()).toEqual(['BOTDEVICE2', 'BOTDEVICE1']));
    expect(fakeBots.epoch).toBe(2);
  });

  it('shows a device whose uploaded keys differ from its signed ones as changed, and never signs them', async () => {
    // BOTDEVICE1 was vouched for with its old keys; the server now shows other keys under its ID.
    const signed = keys(fakeBots.uploaded[0]);
    fakeBots.vouched = [signed];
    fakeBots.epoch = 1;
    fakeBots.uploaded = [{ ...dev('BOTDEVICE1', '1111-2222-3333-4444-5555'), ed25519: 'x'.repeat(43) }, fakeBots.uploaded[1]];
    render(<BotDevices onClose={() => undefined} />);
    expect(await screen.findByText(/Changed: its keys are not the ones you vouched for/)).toBeTruthy();
    expect(screen.queryByText(/^Vouched for/)).toBeNull();
    // It asks for a fresh code, like a new device.
    const [input1, input2] = screen.getAllByLabelText('Code your bot shows');
    const [vouch1, vouch2] = screen.getAllByRole('button', { name: 'Vouch for this device' });
    expect((vouch1 as HTMLButtonElement).disabled).toBe(true);
    // Vouching for the other device keeps BOTDEVICE1's signed keys, not the uploaded ones.
    fireEvent.change(input2, { target: { value: '9999-8888-7777-6666-5555' } });
    fireEvent.click(vouch2);
    await waitFor(() => expect(fakeBots.epoch).toBe(2));
    expect(fakeBots.vouched).toEqual([signed, keys(fakeBots.uploaded[1])]);
    // Only the new code re-vouches for it, with the new keys.
    fireEvent.change(input1, { target: { value: '1111-2222-3333-4444-5555' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Vouch for this device' })[0]);
    await waitFor(() => expect(fakeBots.epoch).toBe(3));
    expect(fakeBots.vouched).toEqual([keys(fakeBots.uploaded[1]), keys(fakeBots.uploaded[0])]);
  });

  it('lets the owner remove a vouched device the bot no longer shows', async () => {
    fakeBots.vouched = [{ device_id: 'GONEDEVICE', curve25519: 'g'.repeat(43), ed25519: 'g'.repeat(43) }];
    fakeBots.epoch = 1;
    render(<BotDevices onClose={() => undefined} />);
    expect(await screen.findByText(/no longer shows it/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(fakeBots.vouched).toEqual([]));
  });

  it('says when the user owns no bots', async () => {
    fakeBots.bots = [];
    render(<BotDevices onClose={() => undefined} />);
    expect(await screen.findByText('You own no bots.')).toBeTruthy();
  });
});
