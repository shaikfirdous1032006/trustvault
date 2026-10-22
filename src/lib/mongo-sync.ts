import { getMongoDb, isMongoConfigured } from '@/lib/mongodb';
import type { LocalStore } from '@/lib/local-db';
import type { AuditEvent } from '@/lib/types';
import type { AnyBulkWriteOperation, Document, Filter, OptionalUnlessRequiredId } from 'mongodb';

let isSyncing = false;
let hasInitialized = false;

function cleanDoc<T extends { id: string }>(doc: Record<string, unknown>): T {
  const { _id, ...rest } = doc;
  return {
    ...rest,
    id: (rest.id as string) || String(_id),
  } as T;
}

/**
 * Fetch all documents, users, permissions, versions, share links, and audit events from MongoDB Atlas.
 */
export async function fetchStoreFromMongo(): Promise<LocalStore | null> {
  if (!isMongoConfigured()) return null;

  try {
    const db = await getMongoDb();

    const [users, documents, permissions, versions, share_links, audit] = await Promise.all([
      db.collection('users').find().toArray(),
      db.collection('documents').find().toArray(),
      db.collection('permissions').find().toArray(),
      db.collection('versions').find().toArray(),
      db.collection('share_links').find().toArray(),
      db.collection('audit').find().sort({ occurred_at: 1 }).toArray(),
    ]);

    // If users collection is empty, the database has not been initialized yet
    if (users.length === 0 && documents.length === 0) {
      return null;
    }

    return {
      users: users.map((d) => cleanDoc(d as Record<string, unknown>)),
      documents: documents.map((d) => cleanDoc(d as Record<string, unknown>)),
      permissions: permissions.map((d) => cleanDoc(d as Record<string, unknown>)),
      versions: versions.map((d) => cleanDoc(d as Record<string, unknown>)),
      share_links: share_links.map((d) => cleanDoc(d as Record<string, unknown>)),
      audit: audit.map((d) => cleanDoc(d as Record<string, unknown>)),
    };
  } catch (error) {
    console.warn('[MongoDB Sync] Failed to fetch from MongoDB Atlas:', error);
    return null;
  }
}

/**
 * Seed or push all store data into MongoDB Atlas collections.
 */
export async function pushStoreToMongo(store: LocalStore): Promise<void> {
  if (!isMongoConfigured()) return;
  if (isSyncing) return;
  isSyncing = true;

  try {
    const db = await getMongoDb();

    // Helper for bulk upsert
    const upsertBatch = async (collectionName: string, items: Array<{ id: string } & Record<string, unknown>>) => {
      if (!items || items.length === 0) return;
      const collection = db.collection(collectionName);
      const operations: AnyBulkWriteOperation<Document>[] = items.map((item) => ({
        replaceOne: {
          filter: { _id: item.id } as unknown as Filter<Document>,
          replacement: { _id: item.id, ...item } as unknown as Document,
          upsert: true,
        },
      }));
      await collection.bulkWrite(operations, { ordered: false });
    };

    await Promise.allSettled([
      upsertBatch('users', store.users as unknown as Array<{ id: string } & Record<string, unknown>>),
      upsertBatch('documents', store.documents as unknown as Array<{ id: string } & Record<string, unknown>>),
      upsertBatch('permissions', store.permissions as unknown as Array<{ id: string } & Record<string, unknown>>),
      upsertBatch('versions', store.versions as unknown as Array<{ id: string } & Record<string, unknown>>),
      upsertBatch('share_links', store.share_links as unknown as Array<{ id: string } & Record<string, unknown>>),
      upsertBatch('audit', store.audit as unknown as Array<{ id: string } & Record<string, unknown>>),
    ]);
  } catch (error) {
    console.warn('[MongoDB Sync] Failed to push store to MongoDB Atlas:', error);
  } finally {
    isSyncing = false;
  }
}

/**
 * Append a single audit event directly into MongoDB Atlas.
 */
export async function pushAuditEventToMongo(event: AuditEvent): Promise<void> {
  if (!isMongoConfigured()) return;

  try {
    const db = await getMongoDb();
    await db.collection('audit').replaceOne(
      { _id: event.id } as unknown as Filter<Document>,
      { _id: event.id, ...event } as unknown as OptionalUnlessRequiredId<Document>,
      { upsert: true }
    );
  } catch (error) {
    console.warn('[MongoDB Sync] Failed to push audit event to MongoDB Atlas:', error);
  }
}

/**
 * Initialize MongoDB connection and synchronize state on startup.
 */
export async function initMongoSync(getInitialStore: () => LocalStore, updateStore: (s: LocalStore) => void) {
  if (hasInitialized || !isMongoConfigured()) return;
  hasInitialized = true;

  try {
    const remoteStore = await fetchStoreFromMongo();
    if (remoteStore) {
      updateStore(remoteStore);
    } else {
      const initial = getInitialStore();
      await pushStoreToMongo(initial);
    }
  } catch (err) {
    console.warn('[MongoDB Sync] Initialization warning:', err);
  }
}
