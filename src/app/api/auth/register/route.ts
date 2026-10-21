
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

const registerSchema = z.object({
  full_name: z.string().trim().min(2).max(100),
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(200),
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
            "Enter a valid name, email, and password of at least 8 characters.",
        },
        { status: 400 }
      );
    }

    const fullName = parsed.data.full_name;
    const email = parsed.data.email.toLowerCase();
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
        role: "viewer" as const,
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

    // Do not promote accounts during public registration.
    // The owner email is reserved for a separate, secure
    // provisioning process rather than self-service registration.
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
        assigned_role: "viewer",
        configured_owner_email: isConfiguredOwner,
      },
    });

    return NextResponse.json(
      {
        success: true,
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
