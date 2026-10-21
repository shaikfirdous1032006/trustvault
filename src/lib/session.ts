
import type { User, UserRole } from '@/lib/types';

export const SESSION_COOKIE = 'tv_session';

export class SessionConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SessionConfigError';
  }
}

export interface SessionPayload {
  id: string;
  email: string;
  role: UserRole;
  full_name: string | null;
  is_active: boolean;
  iat: number;
  exp: number;
}

const MIN_SECRET_LENGTH = 32;
const SESSION_LIFETIME_SECONDS = 60 * 60 * 24;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const ALLOWED_ROLES: readonly UserRole[] = [
  'admin',
  'owner',
  'viewer',
];

function getSecret(): string {
  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < MIN_SECRET_LENGTH) {
    throw new SessionConfigError(
      'SESSION_SECRET must contain at least 32 characters.',
    );
  }

  return secret;
}

function getCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable in this runtime.');
  }

  return globalThis.crypto;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array {
  if (
    !value ||
    !/^[A-Za-z0-9_-]+$/.test(value) ||
    value.length % 4 === 1
  ) {
    throw new Error('Invalid token encoding.');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    (character) => character.charCodeAt(0),
  );
}

function asBufferSource(bytes: Uint8Array): BufferSource {
  return new Uint8Array(bytes) as unknown as BufferSource;
}

async function getSigningKey(): Promise<CryptoKey> {
  const keyBytes = encoder.encode(getSecret());

  return getCrypto().subtle.importKey(
    'raw',
    asBufferSource(keyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

async function signBody(body: string): Promise<Uint8Array> {
  const key = await getSigningKey();
  const bodyBytes = encoder.encode(body);

  const signature = await getCrypto().subtle.sign(
    'HMAC',
    key,
    asBufferSource(bodyBytes),
  );

  return new Uint8Array(signature);
}

export async function createSessionToken(
  user: Pick<
    User,
    'id' | 'email' | 'role' | 'full_name' | 'is_active'
  >,
): Promise<string> {
  if (
    typeof user.id !== 'string' ||
    user.id.length === 0 ||
    typeof user.email !== 'string' ||
    user.email.length === 0 ||
    !ALLOWED_ROLES.includes(user.role)
  ) {
    throw new Error('Invalid session user.');
  }

  if (
    user.full_name !== null &&
    typeof user.full_name !== 'string'
  ) {
    throw new Error('Invalid user name.');
  }

  const now = Math.floor(Date.now() / 1000);

  const payload: SessionPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
    full_name: user.full_name,
    is_active: true,
    iat: now,
    exp: now + SESSION_LIFETIME_SECONDS,
  };

  const body = toBase64Url(
    encoder.encode(JSON.stringify(payload)),
  );

  const signature = toBase64Url(await signBody(body));

  return `${body}.${signature}`;
}

export async function verifySessionToken(
  token: string,
): Promise<(User & { iat: number; exp: number }) | null> {
  try {
    if (
      typeof token !== 'string' ||
      token.length === 0 ||
      token.length > 8192
    ) {
      return null;
    }

    const parts = token.split('.');

    if (parts.length !== 2) {
      return null;
    }

    const [body, signature] = parts;
    const providedSignature = fromBase64Url(signature);

    if (providedSignature.length !== 32) {
      return null;
    }

    const key = await getSigningKey();
    const bodyBytes = encoder.encode(body);

    const valid = await getCrypto().subtle.verify(
      'HMAC',
      key,
      asBufferSource(providedSignature),
      asBufferSource(bodyBytes),
    );

    if (!valid) {
      return null;
    }

    const payloadText = decoder.decode(fromBase64Url(body));
    const payload: unknown = JSON.parse(payloadText);

    if (
      typeof payload !== 'object' ||
      payload === null ||
      Array.isArray(payload)
    ) {
      return null;
    }

    const data = payload as Partial<SessionPayload>;
    const now = Math.floor(Date.now() / 1000);

    if (
      typeof data.id !== 'string' ||
      data.id.length === 0 ||
      typeof data.email !== 'string' ||
      data.email.length === 0 ||
      typeof data.role !== 'string' ||
      !ALLOWED_ROLES.includes(data.role as UserRole) ||
      data.is_active !== true ||
      !(
        typeof data.full_name === 'string' ||
        data.full_name === null
      ) ||
      typeof data.iat !== 'number' ||
      !Number.isSafeInteger(data.iat) ||
      typeof data.exp !== 'number' ||
      !Number.isSafeInteger(data.exp) ||
      data.iat > now + 60 ||
      data.exp <= now ||
      data.exp <= data.iat ||
      data.exp - data.iat > SESSION_LIFETIME_SECONDS
    ) {
      return null;
    }

    return {
      id: data.id,
      email: data.email,
      role: data.role as UserRole,
      full_name: data.full_name,
      is_active: true,
      iat: data.iat,
      exp: data.exp,
      created_at: new Date(data.iat * 1000).toISOString(),
      updated_at: new Date(data.iat * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}
