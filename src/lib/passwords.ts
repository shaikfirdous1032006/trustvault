
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
  } catch {
    // ignore read-only on serverless
  }

  if (!fs.existsSync(CREDENTIALS_PATH)) {
    return {};
  }

  const contents = fs.readFileSync(CREDENTIALS_PATH, "utf8");
  const parsed: unknown = JSON.parse(contents);

  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    throw new Error("Credentials storage has an invalid format");
  }

  return parsed as Record<string, PasswordRecord>;
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

    fs.chmodSync(temporaryPath, 0o600);
    fs.renameSync(temporaryPath, CREDENTIALS_PATH);

    try {
      fs.chmodSync(CREDENTIALS_PATH, 0o600);
    } catch {
      // Some platforms do not support Unix-style file permissions.
    }
  } finally {
    if (fs.existsSync(temporaryPath)) {
      fs.unlinkSync(temporaryPath);
    }
  }
}

export function getPasswordRecord(
  userId: string
): PasswordRecord | undefined {
  const record = readCredentials()[userId];

  return isValidRecord(record) ? record : undefined;
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
