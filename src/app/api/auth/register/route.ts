
import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "node:crypto";
import { z } from "zod";

import { mutateStore } from "@/lib/local-db";
import { isSupabaseConfigured } from "@/lib/supabase/server";
import { getRequestMeta } from "@/lib/auth";
import { logAuditEvent } from "@/lib/audit";
import { checkRateLimit, csrfRejection } from "@/lib/security";
import {
  hashPassword,
  savePasswordRecord,
} from "@/lib/passwords";
import { createSessionToken, SESSION_COOKIE } from "@/lib/session";

const registerSchema = z.object({
  full_name: z.string().trim().min(2).max(100),
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(200),
  role: z.enum(["owner", "viewer", "admin"]).default("viewer"),
});

export async function POST(request: NextRequest) {
  const crossOrigin = csrfRejection(request);

  if (crossOrigin) {
    return crossOrigin;
  }

  if (isSupabaseConfigured()) {
    return NextResponse.json(
      {
        success: false,
        error:
          "Registration through Supabase is not implemented in this endpoint.",
      },
      { status: 501 }
    );
  }

  const { ipAddress, userAgent } = await getRequestMeta();

  const limit = checkRateLimit(
    `register:${ipAddress || "unknown-client"}`,
    5,
    60_000
  );

  if (!limit.allowed) {
    return NextResponse.json(
      {
        success: false,
        error: "Too many registration attempts. Try again later.",
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(
            Math.ceil(limit.resetMs / 1000)
          ),
        },
      }
    );
  }

  try {
    const body = await request.json();
    const parsed = registerSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          success: false,
          error:
            "Enter a valid name, email, password (min 8 chars), and role.",
        },
        { status: 400 }
      );
    }

    const fullName = parsed.data.full_name;
    const email = parsed.data.email.toLowerCase();
    const selectedRole = parsed.data.role;
    const passwordRecord = hashPassword(parsed.data.password);

    // Configure this only for the account you control.
    const ownerEmail = process.env.TRUSTVAULT_OWNER_EMAIL
      ?.trim()
      .toLowerCase();

    const result = await mutateStore((store) => {
      if (
        store.users.some(
          (user) => user.email.toLowerCase() === email
        )
      ) {
        return { error: "EXISTS" as const };
      }

      const now = new Date().toISOString();

      const user = {
        id: randomUUID(),
        email,
        full_name: fullName,
        role: selectedRole,
        is_active: true,
        created_at: now,
        updated_at: now,
      };

      savePasswordRecord(user.id, passwordRecord);
      store.users.push(user);

      return { user };
    });

    if ("error" in result) {
      return NextResponse.json(
        {
          success: false,
          error: "An account with this email already exists.",
        },
        { status: 409 }
      );
    }

    // Persist user and credentials directly to MongoDB Atlas for cloud sync
    try {
      const { getMongoDb, isMongoConfigured } = await import("@/lib/mongodb");
      if (isMongoConfigured()) {
        const db = await getMongoDb();
        await Promise.all([
          db.collection("users").updateOne(
            { email: result.user.email },
            { $set: result.user },
            { upsert: true }
          ),
          db.collection("credentials").updateOne(
            { user_id: result.user.id },
            {
              $set: {
                user_id: result.user.id,
                email: result.user.email,
                salt: passwordRecord.salt,
                hash: passwordRecord.hash,
                updated_at: new Date(),
              },
            },
            { upsert: true }
          ),
        ]);
      }
    } catch {
      // ignore
    }

    const isConfiguredOwner =
      Boolean(ownerEmail) && email === ownerEmail;

    await logAuditEvent({
      actorId: result.user.id,
      actorEmail: result.user.email,
      action: "admin_action",
      result: "allowed",
      ipAddress,
      userAgent,
      details: {
        operation: "account_registration",
        assigned_role: selectedRole,
        configured_owner_email: isConfiguredOwner,
      },
    });

    let token = "";
    try {
      token = await createSessionToken(result.user);
    } catch {
      // ignore
    }

    const response = NextResponse.json(
      {
        success: true,
        autoLogin: Boolean(token),
        message:
          "Account created successfully. Sign in to continue.",
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            full_name: result.user.full_name,
            role: result.user.role,
          },
        },
      },
      { status: 201 }
    );

    if (token) {
      response.cookies.set({
        name: SESSION_COOKIE,
        value: token,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 86400,
      });
    }

    try {
      const { appendCookieAccount } = await import("@/lib/cookie-accounts");
      appendCookieAccount(request, response, {
        user: result.user,
        salt: passwordRecord.salt,
        hash: passwordRecord.hash,
      });
    } catch {
      // ignore
    }

    return response;
  } catch (error) {
    console.error("[AUTH] Registration failed:", error);

    return NextResponse.json(
      {
        success: false,
        error: "Registration failed due to a server error.",
      },
      { status: 500 }
    );
  }
}
