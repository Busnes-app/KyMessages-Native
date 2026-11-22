import { deletePushSubscription, registerPushSubscription } from './client';
import type { ChatPushConfig } from './types';

export type PushState =
  | { kind: 'unsupported' }
  | { kind: 'unavailable' }
  | { kind: 'denied' }
  | { kind: 'disabled' }
  | { kind: 'enabled'; endpoint: string };

function isBrowserPushSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    'Notification' in window
  );
}

function urlBase64ToUint8Array(base64Url: string): Uint8Array<ArrayBuffer> {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(base64);
  const buf = new ArrayBuffer(raw.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function bytesToBase64Url(buf: ArrayBuffer | null): string {
  if (!buf) return '';
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function extractKeys(sub: PushSubscription): { endpoint: string; p256dh: string; auth: string } | null {
  const p256dh = bytesToBase64Url(sub.getKey('p256dh'));
  const auth = bytesToBase64Url(sub.getKey('auth'));
  if (!sub.endpoint || !p256dh || !auth) return null;
  return { endpoint: sub.endpoint, p256dh, auth };
}

async function getReadyRegistration(): Promise<ServiceWorkerRegistration> {
  const existing = await navigator.serviceWorker.getRegistration('/');
  if (!existing) {
    await navigator.serviceWorker.register('/sw.js');
  }
  return navigator.serviceWorker.ready;
}

export async function getBrowserPushState(config: ChatPushConfig): Promise<PushState> {
  if (!isBrowserPushSupported()) return { kind: 'unsupported' };
  if (!config.available || !config.vapid_public_key) return { kind: 'unavailable' };
  if (Notification.permission === 'denied') return { kind: 'denied' };

  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    if (!reg) return { kind: 'disabled' };
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return { kind: 'disabled' };
    return { kind: 'enabled', endpoint: sub.endpoint };
  } catch {
    return { kind: 'disabled' };
  }
}

/**
 * Quietly re-registers an already-granted browser subscription with the server so
 * a fresh login or restored server keeps delivering notifications without re-prompting.
 */
export async function syncExistingPushSubscription(config: ChatPushConfig): Promise<PushState> {
  const state = await getBrowserPushState(config);
  if (state.kind !== 'enabled') return state;

  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    const sub = await reg?.pushManager.getSubscription();
    if (!sub) return { kind: 'disabled' };
    const keys = extractKeys(sub);
    if (!keys) return { kind: 'disabled' };
    await registerPushSubscription(keys);
    return { kind: 'enabled', endpoint: keys.endpoint };
  } catch {
    return state;
  }
}

export async function enableBrowserPush(vapidPublicKey: string): Promise<PushState> {
  if (!isBrowserPushSupported()) return { kind: 'unsupported' };
  if (!vapidPublicKey) return { kind: 'unavailable' };

  const permission =
    Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
  if (permission !== 'granted') {
    return permission === 'denied' ? { kind: 'denied' } : { kind: 'disabled' };
  }

  const reg = await getReadyRegistration();
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
    });
  }
  const keys = extractKeys(sub);
  if (!keys) {
    throw new Error('Browser push subscription did not include encryption keys');
  }
  await registerPushSubscription(keys);
  return { kind: 'enabled', endpoint: keys.endpoint };
}

export async function disableBrowserPush(): Promise<PushState> {
  if (!isBrowserPushSupported()) return { kind: 'unsupported' };
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    const sub = await reg?.pushManager.getSubscription();
    if (sub) {
      const endpoint = sub.endpoint;
      await Promise.allSettled([deletePushSubscription(endpoint), sub.unsubscribe()]);
    }
  } catch {
    // Best-effort unsubscribe.
  }
  return Notification.permission === 'denied' ? { kind: 'denied' } : { kind: 'disabled' };
}
