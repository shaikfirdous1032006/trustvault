import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

export type PasswordRecord = {
  salt: string;
  hash: string;
};

function resolveDataDir(): string {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    return path.join(os.tmpdir(), ".data");
  }
  return path.join(process.cwd(), ".data");
}

const DATA_DIR = resolveDataDir();
const CREDENTIALS_PATH = path.join(DATA_DIR, "credentials.json");

function readCredentials(): Record<string, PasswordRecord> {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(CREDENTIALS_PATH)) {
      const contents = fs.readFileSync(CREDENTIALS_PATH, "utf8");
      const parsed: unknown = JSON.parse(contents);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, PasswordRecord>;
      }
    }
  } catch {
    // If reading fails or file is empty, return empty map
  }

  return {};
}

function isValidRecord(value: unknown): value is PasswordRecord {
  if (!value || typeof value !== "object") {
    return false;
  }

  const record = value as Partial<PasswordRecord>;

  return (
    typeof record.salt === "string" &&
    /^[a-f0-9]{32}$/i.test(record.salt) &&
    typeof record.hash === "string" &&
    /^[a-f0-9]{128}$/i.test(record.hash)
  );
}

export function hashPassword(password: string): PasswordRecord {
  if (typeof password !== "string" || password.length < 8 || password.length > 200) {
    throw new Error("Password must be between 8 and 200 characters");
  }

  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");

  return { salt, hash };
}

export function savePasswordRecord(
  userId: string,
  record: PasswordRecord
): void {
  if (!userId || !isValidRecord(record)) {
    throw new Error("Invalid user ID or password record");
  }

  const credentials = readCredentials();
  credentials[userId] = record;

  fs.mkdirSync(DATA_DIR, { recursive: true });

  const temporaryPath = path.join(
    DATA_DIR,
    `credentials-${randomBytes(12).toString("hex")}.tmp`
  );

  try {
    fs.writeFileSync(
      temporaryPath,
      JSON.stringify(credentials, null, 2),
      { encoding: "utf8", mode: 0o600, flag: "wx" }
    );

    try {
      fs.chmodSync(temporaryPath, 0o600);
    } catch {
      // Ignored on platforms without Unix file mode support
    }

    try {
      fs.renameSync(temporaryPath, CREDENTIALS_PATH);
    } catch {
      // Robust fallback on Windows/OneDrive where atomic rename over existing file can fail
      fs.copyFileSync(temporaryPath, CREDENTIALS_PATH);
    }

    try {
      fs.chmodSync(CREDENTIALS_PATH, 0o600);
    } catch {
      // Ignored on platforms without Unix file mode support
    }
    try {
      import('@/lib/mongodb').then(async ({ getMongoDb, isMongoConfigured }) => {
        if (isMongoConfigured()) {
          const db = await getMongoDb();
          await db.collection('credentials').updateOne(
            { user_id: userId },
            { $set: { user_id: userId, salt: record.salt, hash: record.hash, updated_at: new Date() } },
            { upsert: true }
          );
        }
      }).catch(() => {});
    } catch {
      // Ignored
    }
  } finally {
    if (fs.existsSync(temporaryPath)) {
      try {
        fs.unlinkSync(temporaryPath);
      } catch {
        // Ignored
      }
    }
  }
}

export function getPasswordRecord(
  userId: string
): PasswordRecord | undefined {
  const record = readCredentials()[userId];

  return isValidRecord(record) ? record : undefined;
}

export async function getPasswordRecordAsync(
  userId: string
): Promise<PasswordRecord | undefined> {
  const local = getPasswordRecord(userId);
  if (local) return local;

  try {
    const { getMongoDb, isMongoConfigured } = await import('@/lib/mongodb');
    if (isMongoConfigured()) {
      const db = await getMongoDb();
      const doc = await db.collection('credentials').findOne({ user_id: userId });
      if (doc && isValidRecord(doc)) {
        return { salt: doc.salt as string, hash: doc.hash as string };
      }
    }
  } catch {
    // Ignored
  }

  return undefined;
}

export function verifyPassword(
  password: string,
  record: PasswordRecord
): boolean {
  try {
    if (
      typeof password !== "string" ||
      password.length > 200 ||
      !isValidRecord(record)
    ) {
      return false;
    }

    const expected = Buffer.from(record.hash, "hex");
    const actual = scryptSync(password, record.salt, 64);

    return (
      expected.length === actual.length &&
      timingSafeEqual(actual, expected)
    );
  } catch {
    return false;
  }
}
