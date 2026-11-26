import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fake from '../../chat/e2eeFake';
import { EncryptionIdentityGate, IdentityChangedBanner, SetUpEncryption, useIdentityStatus, VerifyAnotherDevice, VerifyThisDevice } from './EncryptionIdentity';

function Gate() {
  const [gate, refresh] = useIdentityStatus(true);
  return <EncryptionIdentityGate gate={gate} refresh={refresh} />;
}

vi.mock('../../chat/e2ee', () => import('../../chat/e2eeFake'));
vi.mock('qrcode', () => ({ default: { toDataURL: async () => 'data:image/png;base64,AAAA' } }));

afterEach(() => {
  cleanup();
  fake.resetFakeE2EE();
  vi.restoreAllMocks();
});

describe('identity screens', () => {
  it('uploads the identity only after the user confirms they saved the recovery key', async () => {
    const commit = vi.fn(async () => undefined);
    vi.spyOn(fake, 'prepareIdentity').mockResolvedValue({ recoveryKey: 'K1K1 K2K2', commit });
    const done = vi.fn();
    render(<SetUpEncryption onDone={done} onClose={() => undefined} />);
    expect(await screen.findByTestId('recovery-key')).toHaveProperty('textContent', 'K1K1 K2K2');
    const go = screen.getByRole('button', { name: 'Continue' });
    expect(go).toHaveProperty('disabled', true);
    fireEvent.click(go);
    expect(commit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox', { name: /I saved my recovery key/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(done).toHaveBeenCalled());
    expect(commit).toHaveBeenCalledTimes(1);
  });

  it('offers a device without an identity the setup, without blocking the page, and a verified device nothing', async () => {
    fake.setFakeIdentity({ state: 'none', quarantined: false });
    const { unmount } = render(<Gate />);
    fireEvent.click(await screen.findByRole('button', { name: 'Set up encryption' }));
    expect(await screen.findByText('Save your recovery key')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Not now' }));
    expect(screen.queryByText('Save your recovery key')).toBeNull();
    expect(screen.getByRole('button', { name: 'Set up encryption' })).toBeTruthy();
    unmount();
    fake.setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false });
    const { container } = render(<Gate />);
    await act(async () => undefined);
    expect(container.textContent).toBe('');
    expect(screen.queryByText('Verify this device')).toBeNull();
  });

  it('verifies a new device with a recovery key', async () => {
    fake.setFakeIdentity({ state: 'unverified', fingerprint: 'ab'.repeat(32), quarantined: false });
    const restore = vi.spyOn(fake, 'restoreIdentity').mockResolvedValue(3);
    render(<Gate />);
    fireEvent.click(await screen.findByRole('button', { name: 'Verify this device' }));
    fireEvent.click(await screen.findByRole('radio', { name: /recovery key/ }));
    fireEvent.change(screen.getByLabelText('Recovery key'), { target: { value: 'my key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(restore).toHaveBeenCalledWith('my key'));
  });

  it('shows the comparison code and sends keys only when the user says the codes match', async () => {
    const approve = vi.fn(async () => undefined);
    const poll = vi.fn().mockResolvedValueOnce(undefined).mockResolvedValue({ code: '424242', device: 'NEWDEVICE' });
    vi.spyOn(fake, 'offerVerification').mockResolvedValue({ text: 'QRTEXT', expiresInMs: 60_000, poll, approve, cancel: async () => undefined });
    render(<VerifyAnotherDevice onClose={() => undefined} />);
    expect((await screen.findByTestId('verification-code')).textContent).toBe('QRTEXT');
    expect(approve).not.toHaveBeenCalled();
    expect((await screen.findByTestId('comparison-code', {}, { timeout: 3000 })).textContent).toBe('424242');
    fireEvent.click(screen.getByRole('button', { name: 'The codes match' }));
    await waitFor(() => expect(approve).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/new device is verified/)).toBeTruthy();
  });

  it('warns in a room whose member changed identity until the viewer accepts it', async () => {
    fake.setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false }, [
      { user_id: 'u_bob', fingerprint: 'cd'.repeat(32), previous: 'ef'.repeat(32) },
      { user_id: 'u_elsewhere', fingerprint: 'cd'.repeat(32), previous: 'ef'.repeat(32) },
    ]);
    render(<IdentityChangedBanner memberIds={['u_alice', 'u_bob']} nameOf={(id) => (id === 'u_bob' ? 'Bob' : id)} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Bob’s identity changed');
    expect(screen.queryByText(/u_elsewhere/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Accept new identity' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });

  it('takes keys on a new device only after the user confirms the codes match', async () => {
    const finish = vi.fn(async () => 2);
    vi.spyOn(fake, 'joinVerification').mockResolvedValue({ code: '135790', finish, cancel: async () => undefined });
    const done = vi.fn();
    render(<VerifyThisDevice fingerprint={'ab'.repeat(32)} onDone={done} onClose={() => undefined} onReset={() => undefined} />);
    fireEvent.change(screen.getByLabelText(/Verification code/), { target: { value: 'QRTEXT' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect((await screen.findByTestId('comparison-code')).textContent).toBe('135790');
    expect(finish).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'The codes match' }));
    await waitFor(() => expect(done).toHaveBeenCalledWith(2));
  });

  it('says when the identity cannot be checked, and retries', async () => {
    const status = vi.spyOn(fake, 'identityStatus').mockRejectedValueOnce(new Error('offline'));
    render(<Gate />);
    expect((await screen.findByRole('alert')).textContent).toContain('offline');
    fake.setFakeIdentity({ state: 'none', quarantined: false });
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('button', { name: 'Set up encryption' })).toBeTruthy();
    expect(status).toHaveBeenCalled();
  });

  it('shows the whole new fingerprint and refuses an accept for a change that moved on', async () => {
    fake.setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false }, [
      { user_id: 'u_bob', fingerprint: '12'.repeat(32), previous: 'ef'.repeat(32) },
    ]);
    render(<IdentityChangedBanner memberIds={['u_bob']} nameOf={() => 'Bob'} />);
    expect((await screen.findByTestId('new-fingerprint')).textContent?.replace(/ /g, '')).toBe('12'.repeat(32));
    // Another tab replaced the candidate after this banner rendered.
    fake.setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false }, [
      { user_id: 'u_bob', fingerprint: '34'.repeat(32), previous: 'ef'.repeat(32) },
    ]);
    const accept = vi.spyOn(fake, 'acceptIdentity');
    fireEvent.click(screen.getByRole('button', { name: 'Accept new identity' }));
    await waitFor(() => expect(accept).toHaveBeenCalledWith('u_bob', 'ef'.repeat(32), expect.any(String)));
  });

  it('says verified only once the new device has confirmed, not when the keys are sent', async () => {
    const approve = vi.fn(async () => undefined);
    vi.spyOn(fake, 'offerVerification').mockResolvedValue({ text: 'QRTEXT', expiresInMs: 60_000, poll: async () => ({ code: '111222', device: 'NEWDEVICE' }), approve, cancel: async () => undefined });
    const confirmed = vi.spyOn(fake, 'ownDeviceVerified').mockResolvedValueOnce(false).mockResolvedValue(true);
    render(<VerifyAnotherDevice onClose={() => undefined} />);
    fireEvent.click(await screen.findByRole('button', { name: 'The codes match' }));
    expect(await screen.findByText(/Waiting for the new device to confirm/)).toBeTruthy();
    expect(await screen.findByText(/new device is verified/, {}, { timeout: 4000 })).toBeTruthy();
    expect(confirmed).toHaveBeenCalledWith('NEWDEVICE');
  });

  it('offers a reset when the server rolled back or forked this identity, and says what it does', async () => {
    fake.setFakeIdentity({ state: 'verified', fingerprint: 'f'.repeat(64), restoring: false, backupFull: false, problem: 'rollback' });
    render(<Gate />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(/older list of your devices/);
    expect(alert.textContent).toMatch(/everyone you share rooms with will see/);
    fireEvent.click(screen.getByRole('button', { name: 'Reset identity' }));
    expect(await screen.findByText('Reset your encryption identity')).toBeTruthy();
  });

  it('shows waiting encryption work with a retry, and clears once it ran', async () => {
    fake.setFakePending(true);
    render(<Gate />);
    expect(await screen.findByTestId('encryption-pending')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Retry now' }));
    await waitFor(() => expect(screen.queryByTestId('encryption-pending')).toBeNull());
  });

  it('closes while waiting for the new device without cancelling the keys it sent, and stops watching', async () => {
    const cancel = vi.fn(async () => undefined);
    vi.spyOn(fake, 'offerVerification').mockResolvedValue({ text: 'QRTEXT', expiresInMs: 60_000, poll: async () => ({ code: '111222', device: 'NEWDEVICE' }), approve: async () => undefined, cancel });
    const confirmed = vi.spyOn(fake, 'ownDeviceVerified').mockResolvedValue(false);
    const closed = vi.fn();
    render(<VerifyAnotherDevice onClose={closed} />);
    fireEvent.click(await screen.findByRole('button', { name: 'The codes match' }));
    expect(await screen.findByText(/Waiting for the new device to confirm/)).toBeTruthy();
    const close = screen.getAllByRole('button', { name: 'Close' }).find((b) => b.textContent === 'Close')!;
    expect(close).toHaveProperty('disabled', false);
    fireEvent.click(close);
    expect(closed).toHaveBeenCalled();
    expect(cancel).not.toHaveBeenCalled();
    const calls = confirmed.mock.calls.length;
    await new Promise((r) => setTimeout(r, 1700));
    expect(confirmed.mock.calls.length).toBe(calls);
  });

  it('cancels a pairing closed before any keys were sent, and drops its poll', async () => {
    const cancel = vi.fn(async () => undefined);
    let seen: AbortSignal | undefined;
    const poll = vi.fn(async (signal?: AbortSignal) => {
      seen = signal;
      return undefined;
    });
    vi.spyOn(fake, 'offerVerification').mockResolvedValue({ text: 'QRTEXT', expiresInMs: 60_000, poll, approve: async () => undefined, cancel });
    const { unmount } = render(<VerifyAnotherDevice onClose={() => undefined} />);
    await screen.findByTestId('verification-code');
    await waitFor(() => expect(poll).toHaveBeenCalled());
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(cancel).toHaveBeenCalled();
    expect(seen?.aborted).toBe(true);
    unmount();
  });

  it('keeps polling under StrictMode, whose effects run twice', async () => {
    const poll = vi.fn().mockResolvedValueOnce(undefined).mockResolvedValue({ code: '565656', device: 'NEWDEVICE' });
    vi.spyOn(fake, 'offerVerification').mockResolvedValue({ text: 'QRTEXT', expiresInMs: 60_000, poll, approve: async () => undefined, cancel: async () => undefined });
    render(<StrictMode><VerifyAnotherDevice onClose={() => undefined} /></StrictMode>);
    expect((await screen.findByTestId('comparison-code', {}, { timeout: 3000 })).textContent).toBe('565656');
    for (const [signal] of poll.mock.calls.slice(-1)) expect((signal as AbortSignal).aborted).toBe(false);
  });
});
