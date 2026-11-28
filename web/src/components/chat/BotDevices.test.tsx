import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BotDevices } from './BotDevices';
import { fakeBots } from '../../chat/e2eeFake';

vi.mock('../../chat/e2ee', () => import('../../chat/e2eeFake'));

const dev = (id: string, code: string) => ({ device_id: id, curve25519: 'c'.repeat(43), ed25519: 'e'.repeat(43), code });

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
    await waitFor(() => expect(fakeBots.vouched).toEqual(['BOTDEVICE1']));
    expect(await screen.findByText(/^Vouched for/)).toBeTruthy();
    // Vouching for the second keeps the first; removing it signs a list without it.
    const [input2] = await screen.findAllByLabelText('Code your bot shows');
    fireEvent.change(input2, { target: { value: '9999-8888-7777-6666-5555' } });
    fireEvent.click(screen.getByRole('button', { name: 'Vouch for this device' }));
    await waitFor(() => expect(fakeBots.vouched).toEqual(['BOTDEVICE1', 'BOTDEVICE2']));
    fireEvent.click((await screen.findAllByRole('button', { name: 'Remove' }))[0]);
    await waitFor(() => expect(fakeBots.vouched).toEqual(['BOTDEVICE2']));
  });

  it('says when the user owns no bots', async () => {
    fakeBots.bots = [];
    render(<BotDevices onClose={() => undefined} />);
    expect(await screen.findByText('You own no bots.')).toBeTruthy();
  });
});
