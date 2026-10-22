import { getMongoDb, isMongoConfigured } from '@/lib/mongodb';
import type { LocalStore } from '@/lib/local-db';
import type { AuditEvent } from '@/lib/types';
import type { AnyBulkWriteOperation, Document, Filter, OptionalUnlessRequiredId } from 'mongodb';

let isSyncing = false;
let hasInitialized = false;

export interface MongoEntity extends Document {
  _id: string;
  [key: string]: unknown;
}

function cleanDoc<T extends { id: string }>(doc: Document): T {
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
      db.collection<MongoEntity>('users').find().toArray(),
      db.collection<MongoEntity>('documents').find().toArray(),
      db.collection<MongoEntity>('permissions').find().toArray(),
      db.collection<MongoEntity>('versions').find().toArray(),
      db.collection<MongoEntity>('share_links').find().toArray(),
      db.collection<MongoEntity>('audit').find().sort({ occurred_at: 1 }).toArray(),
    ]);

    // If users collection is empty, the database has not been initialized yet
    if (users.length === 0 && documents.length === 0) {
      return null;
    }

    return {
      users: users.map((d) => cleanDoc(d)),
      documents: documents.map((d) => cleanDoc(d)),
      permissions: permissions.map((d) => cleanDoc(d)),
      versions: versions.map((d) => cleanDoc(d)),
      share_links: share_links.map((d) => cleanDoc(d)),
      audit: audit.map((d) => cleanDoc(d)),
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
    const upsertBatch = async <T extends { id: string }>(collectionName: string, items: T[]) => {
      if (!items || items.length === 0) return;
      const collection = db.collection<MongoEntity>(collectionName);
      const operations: AnyBulkWriteOperation<MongoEntity>[] = items.map((item) => ({
        replaceOne: {
          filter: { _id: item.id },
          replacement: { _id: item.id, ...item },
          upsert: true,
        },
      }));
      await collection.bulkWrite(operations, { ordered: false });
    };

    await Promise.allSettled([
      upsertBatch('users', store.users),
      upsertBatch('documents', store.documents),
      upsertBatch('permissions', store.permissions),
      upsertBatch('versions', store.versions),
      upsertBatch('share_links', store.share_links),
      upsertBatch('audit', store.audit),
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
    const collection = db.collection<MongoEntity>('audit');
    await collection.replaceOne(
      { _id: event.id },
      { _id: event.id, ...event },
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
