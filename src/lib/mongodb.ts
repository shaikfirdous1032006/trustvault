import { MongoClient, Db } from 'mongodb';

function getMongoUri(): string {
  return (
    process.env.MONGODB_URI ||
    'mongodb+srv://shaikmuskan02122003_db_user:LuvbYm4iqALsKENO@cluster0.m0y0ghy.mongodb.net/trustvault?retryWrites=true&w=majority&appName=Cluster0'
  ).trim();
}

function getDbName(): string {
  return (process.env.MONGODB_DB || 'trustvault').trim();
}

let client: MongoClient | null = null;
let clientPromise: Promise<MongoClient> | null = null;

declare global {
  var _mongoClientPromise: Promise<MongoClient> | undefined;
}

export function isMongoConfigured(): boolean {
  if (process.env.NODE_ENV === 'test' && !process.env.MONGODB_TEST) {
    return false;
  }
  const uri = getMongoUri();
  return Boolean(uri && uri.startsWith('mongodb'));
}

export async function getMongoClient(): Promise<MongoClient> {
  if (!isMongoConfigured()) {
    throw new Error('MONGODB_URI environment variable is not configured');
  }

  const mongoUri = getMongoUri();

  if (process.env.NODE_ENV === 'development') {
    // In development mode, use a global variable to preserve connection across HMR
    if (!global._mongoClientPromise) {
      client = new MongoClient(mongoUri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
      });
      global._mongoClientPromise = client.connect();
    }
    return global._mongoClientPromise;
  } else {
    // In production or test
    if (!clientPromise) {
      client = new MongoClient(mongoUri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
      });
      clientPromise = client.connect();
    }
    return clientPromise;
  }
}

export async function getMongoDb(): Promise<Db> {
  const c = await getMongoClient();
  return c.db(getDbName());
}

export async function checkMongoConnection(): Promise<{
  connected: boolean;
  dbName: string;
  cluster: string;
  latencyMs?: number;
  collections?: string[];
  error?: string;
}> {
  const dbName = getDbName();
  if (!isMongoConfigured()) {
    return {
      connected: false,
      dbName,
      cluster: 'not-configured',
      error: 'MONGODB_URI is not set',
    };
  }

  const start = Date.now();
  try {
    const db = await getMongoDb();
    // Ping the admin or db to check connection and latency
    await db.command({ ping: 1 });
    const latencyMs = Date.now() - start;

    const collectionsInfo = await db.listCollections().toArray();
    const collections = collectionsInfo.map((c) => c.name);

    // Extract cluster host from URI for display without exposing credentials
    let cluster = 'cluster0.m0y0ghy.mongodb.net';
    try {
      const match = getMongoUri().match(/@([^/?]+)/);
      if (match && match[1]) {
        cluster = match[1];
      }
    } catch {
      // fallback
    }

    return {
      connected: true,
      dbName,
      cluster,
      latencyMs,
      collections,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to connect to MongoDB Atlas';
    return {
      connected: false,
      dbName,
      cluster: 'cluster0.m0y0ghy.mongodb.net',
      error: message,
    };
  }
}
