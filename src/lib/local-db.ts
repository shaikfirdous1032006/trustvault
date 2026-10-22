import fs from 'fs';
import path from 'path';
import os from 'os';
import { createHash, randomUUID } from 'crypto';
import type {
  AuditEvent,
  Document,
  DocumentPermission,
  DocumentVersion,
  ShareLink,
  User,
} from '@/lib/types';

function resolveDataDir(): string {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    return path.join(os.tmpdir(), '.data');
  }
  return path.join(process.cwd(), '.data');
}

let DATA_DIR = resolveDataDir();
let STORE_PATH = path.join(DATA_DIR, 'store.json');
let FILES_DIR = path.join(DATA_DIR, 'files');

export const DEMO_IDS = {
  admin: 'usr-admin-demo-001',
  owner: 'usr-owner-demo-002',
  viewer: 'usr-viewer-demo-003',
  docShared: 'demo-doc-1',
  docPrivate: 'demo-doc-2',
  grantViewer: 'perm-viewer-read-001',
};

export interface LocalStore {
  users: User[];
  documents: Document[];
  permissions: DocumentPermission[];
  versions: DocumentVersion[];
  share_links: ShareLink[];
  audit: AuditEvent[];
}

let writeChain: Promise<unknown> = Promise.resolve();

function withLock<T>(fn: () => T): Promise<T> {
  const next = writeChain.then(fn, fn);
  writeChain = next.then(
    () => undefined,
    () => undefined
  );
  return next;
}

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function computeEventHash(
  occurredAt: string,
  actorId: string | null,
  documentId: string | null,
  action: string,
  result: string,
  detailsJson: string,
  prevHash: string | null
): string {
  return sha256(
    [occurredAt, actorId ?? '', documentId ?? '', action, result, detailsJson, prevHash ?? ''].join('|')
  );
}

function ensureDirs() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.mkdirSync(FILES_DIR, { recursive: true });
  } catch {
    DATA_DIR = path.join(os.tmpdir(), '.data');
    STORE_PATH = path.join(DATA_DIR, 'store.json');
    FILES_DIR = path.join(DATA_DIR, 'files');
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.mkdirSync(FILES_DIR, { recursive: true });
    } catch {
      // ignore
    }
  }
}

function seedFile(name: string, contents: string): { storagePath: string; size: number; checksum: string } {
  ensureDirs();
  const storagePath = `seed/${name}`;
  const full = path.join(FILES_DIR, storagePath);
  try {
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, contents, 'utf8');
  } catch {
    // ignore filesystem write errors on serverless environments
  }
  const buf = Buffer.from(contents, 'utf8');
  return {
    storagePath,
    size: buf.length,
    checksum: createHash('sha256').update(buf).digest('hex'),
  };
}

function seedStore(): LocalStore {
  ensureDirs();
  const earlier = new Date(Date.now() - 3600_000).toISOString();
  const earlier2 = new Date(Date.now() - 7200_000).toISOString();

  const shared = seedFile(
    'Q3_Financial_Audit.txt',
    'TRUSTVAULT CONFIDENTIAL\nQ3 2026 Financial Audit & Forecast\nThis file is shared with viewer@example.com (read only).\n'
  );
  const priv = seedFile(
    'Zero_Trust_Architecture.txt',
    'TRUSTVAULT CONFIDENTIAL\nSecurity & Zero-Trust Architecture\nThis file is NOT shared with the viewer.\n'
  );

  const users: User[] = [
    {
      id: DEMO_IDS.admin,
      email: 'admin@example.com',
      full_name: 'Platform Administrator',
      role: 'admin',
      is_active: true,
      created_at: earlier2,
      updated_at: earlier2,
    },
    {
      id: DEMO_IDS.owner,
      email: 'owner@example.com',
      full_name: 'Document Owner',
      role: 'owner',
      is_active: true,
      created_at: earlier2,
      updated_at: earlier2,
    },
    {
      id: DEMO_IDS.viewer,
      email: 'viewer@example.com',
      full_name: 'Document Viewer',
      role: 'viewer',
      is_active: true,
      created_at: earlier2,
      updated_at: earlier2,
    },
    {
      id: 'b1141308-259c-4ebe-85bc-10056166b582',
      email: 'shaikfirdous1036@gmail.com',
      full_name: 'firdous',
      role: 'owner',
      is_active: true,
      created_at: earlier2,
      updated_at: earlier2,
    },
  ];

  const documents: Document[] = [
    {
      id: DEMO_IDS.docShared,
      owner_id: DEMO_IDS.owner,
      title: 'Q3 2026 Financial Audit & Forecast',
      description: 'Highly confidential corporate audit and fiscal forecast.',
      category: 'financial',
      storage_path: shared.storagePath,
      file_name: 'Q3_Financial_Audit.txt',
      file_size: shared.size,
      mime_type: 'text/plain',
      checksum: shared.checksum,
      current_version: 1,
      is_deleted: false,
      deleted_at: null,
      deleted_by: null,
      created_at: earlier,
      updated_at: earlier,
    },
    {
      id: DEMO_IDS.docPrivate,
      owner_id: DEMO_IDS.owner,
      title: 'Security & Zero-Trust Architecture',
      description: 'Technical specification for the zero-trust boundary.',
      category: 'technical',
      storage_path: priv.storagePath,
      file_name: 'Zero_Trust_Architecture.txt',
      file_size: priv.size,
      mime_type: 'text/plain',
      checksum: priv.checksum,
      current_version: 1,
      is_deleted: false,
      deleted_at: null,
      deleted_by: null,
      created_at: earlier2,
      updated_at: earlier2,
    },
  ];

  const permissions: DocumentPermission[] = [
    {
      id: DEMO_IDS.grantViewer,
      document_id: DEMO_IDS.docShared,
      user_id: DEMO_IDS.viewer,
      permission_level: 'read',
      granted_by: DEMO_IDS.owner,
      granted_at: earlier,
      revoked_at: null,
      revoked_by: null,
      expires_at: null,
    },
  ];

  const versions: DocumentVersion[] = documents.map((d) => ({
    id: `ver-${d.id}-1`,
    document_id: d.id,
    version_number: 1,
    storage_path: d.storage_path,
    file_name: d.file_name,
    file_size: d.file_size,
    mime_type: d.mime_type,
    checksum: d.checksum,
    uploaded_by: DEMO_IDS.owner,
    change_notes: 'Initial upload',
    created_at: d.created_at,
  }));

  const store: LocalStore = {
    users,
    documents,
    permissions,
    versions,
    share_links: [],
    audit: [],
  };

  const seedEvents: Array<Omit<AuditEvent, 'id' | 'event_hash' | 'prev_hash' | 'ip_hash' | 'user_agent_hash' | 'request_id'>> = [
    {
      occurred_at: earlier2,
      actor_id: DEMO_IDS.owner,
      actor_email: 'owner@example.com',
      document_id: DEMO_IDS.docPrivate,
      action: 'upload',
      result: 'allowed',
      details_jsonb: { file_name: priv.storagePath },
    },
    {
      occurred_at: earlier,
      actor_id: DEMO_IDS.owner,
      actor_email: 'owner@example.com',
      document_id: DEMO_IDS.docShared,
      action: 'upload',
      result: 'allowed',
      details_jsonb: { file_name: shared.storagePath },
    },
    {
      occurred_at: new Date(Date.now() - 3000_000).toISOString(),
      actor_id: DEMO_IDS.owner,
      actor_email: 'owner@example.com',
      document_id: DEMO_IDS.docShared,
      action: 'permission_grant',
      result: 'allowed',
      details_jsonb: { target_user_email: 'viewer@example.com', permission_level: 'read' },
    },
  ];

  let prev: string | null = null;
  for (const event of seedEvents) {
    const detailsJson = JSON.stringify(event.details_jsonb);
    const event_hash = computeEventHash(
      event.occurred_at,
      event.actor_id,
      event.document_id,
      event.action,
      event.result,
      detailsJson,
      prev
    );
    store.audit.push({
      id: randomUUID(),
      occurred_at: event.occurred_at,
      actor_id: event.actor_id,
      actor_email: event.actor_email,
      document_id: event.document_id,
      action: event.action,
      result: event.result,
      ip_hash: null,
      user_agent_hash: null,
      request_id: randomUUID(),
      details_jsonb: event.details_jsonb,
      prev_hash: prev,
      event_hash,
    });
    prev = event_hash;
  }

  return store;
}

import {
  initMongoSync,
  pushStoreToMongo,
  pushAuditEventToMongo,
  fetchStoreFromMongo,
} from '@/lib/mongo-sync';

function readStore(): LocalStore {
  ensureDirs();
  if (!fs.existsSync(STORE_PATH)) {
    const seeded = seedStore();
    try {
      fs.writeFileSync(STORE_PATH, JSON.stringify(seeded, null, 2));
    } catch {
      // ignore
    }
    void initMongoSync(() => seeded, (s) => writeStore(s, false));
    return seeded;
  }
  try {
    const store = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')) as LocalStore;
    // Stores written before share links existed have no key for them; an undefined
    // array here would crash the first read that touches it.
    if (!Array.isArray(store.share_links)) store.share_links = [];
    void initMongoSync(() => store, (s) => writeStore(s, false));
    return store;
  } catch {
    const seeded = seedStore();
    void initMongoSync(() => seeded, (s) => writeStore(s, false));
    return seeded;
  }
}

function writeStore(store: LocalStore, syncMongo = true) {
  ensureDirs();
  try {
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
  } catch {
    // ignore
  }
  if (syncMongo) {
    void pushStoreToMongo(store);
  }
}

export function getStore(): LocalStore {
  return readStore();
}

export async function syncMongoStore(): Promise<boolean> {
  try {
    const remote = await fetchStoreFromMongo();
    if (remote) {
      writeStore(remote, false);
      return true;
    } else {
      const current = readStore();
      await pushStoreToMongo(current);
      return true;
    }
  } catch {
    return false;
  }
}


export function mutateStore<T>(mutator: (store: LocalStore) => T): Promise<T> {
  return withLock(() => {
    const store = readStore();
    const result = mutator(store);
    writeStore(store);
    return result;
  });
}

export function withUser(doc: Document, store: LocalStore = readStore()): Document {
  const owner = store.users.find((u) => u.id === doc.owner_id);
  return { ...doc, owner };
}

export function withPermissionUsers(
  perm: DocumentPermission,
  store: LocalStore = readStore()
): DocumentPermission {
  return {
    ...perm,
    user: store.users.find((u) => u.id === perm.user_id),
    grantor: store.users.find((u) => u.id === perm.granted_by),
  };
}

export function findUserByEmail(email: string): User | undefined {
  return readStore().users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

export function findUserById(id: string): User | undefined {
  return readStore().users.find((u) => u.id === id);
}

export function getDocument(id: string): Document | undefined {
  return readStore().documents.find((d) => d.id === id);
}

export function getPermissionsForDocument(documentId: string): DocumentPermission[] {
  return readStore().permissions.filter((p) => p.document_id === documentId);
}

export function getShareLinksForDocument(documentId: string): ShareLink[] {
  return readStore().share_links.filter((l) => l.document_id === documentId);
}

export function findShareLinkByTokenHash(tokenHash: string): ShareLink | undefined {
  return readStore().share_links.find((l) => l.token_hash === tokenHash);
}

export function getShareLinkById(id: string): ShareLink | undefined {
  return readStore().share_links.find((l) => l.id === id);
}

export function putFile(storagePath: string, bytes: Buffer) {
  ensureDirs();
  const full = path.join(FILES_DIR, storagePath);
  try {
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, bytes);
  } catch {
    // ignore
  }
}

export function readFileBytes(storagePath: string): Buffer | null {
  const full = path.join(FILES_DIR, storagePath);
  if (!fs.existsSync(full)) return null;
  return fs.readFileSync(full);
}

/**
 * Append an audit event through the same write lock that serialises every other
 * mutation, and always derive prev_hash/event_hash from the current head so a
 * caller cannot inject its own chain position. The lock closes the read-modify-
 * write window in-process; it does not make the JSON file safe against two
 * processes writing at once — that is documented in THREATS.md.
 */
export async function appendAudit(
  event: Omit<AuditEvent, 'id' | 'event_hash' | 'prev_hash'>
): Promise<AuditEvent> {
  return withLock(() => {
    const store = readStore();
    const prevHash = store.audit[store.audit.length - 1]?.event_hash ?? null;
    const detailsJson = JSON.stringify(event.details_jsonb || {});
    const eventHash = computeEventHash(
      event.occurred_at,
      event.actor_id,
      event.document_id,
      event.action,
      event.result,
      detailsJson,
      prevHash
    );

    const created: AuditEvent = {
      ...event,
      id: randomUUID(),
      prev_hash: prevHash,
      event_hash: eventHash,
    };

    store.audit.push(created);
    writeStore(store, false);
    void pushAuditEventToMongo(created);
    return created;
  });
}

export { computeEventHash, sha256 };
