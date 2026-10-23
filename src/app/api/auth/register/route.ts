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
import type { User } from "@/lib/types";

const registerSchema = z.object({
  full_name: z.string().trim().min(2, "Name must be at least 2 characters").max(100),
  email: z.string().trim().email("Invalid email address").max(254),
  password: z.string().min(8, "Password must be at least 8 characters").max(200),
  role: z.enum(["owner", "viewer"]).default("viewer"),
});

export async function POST(request: NextRequest) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) {
    return crossOrigin;
  }

  const { ipAddress, userAgent } = await getRequestMeta();

  const limit = checkRateLimit(
    `register:${ipAddress || "unknown-client"}`,
    10,
    60_000
  );

  if (!limit.allowed) {
    await logAuditEvent({
      actorId: null,
      actorEmail: null,
      action: "register_failure",
      result: "denied",
      ipAddress,
      userAgent,
      details: { reason: "Rate limit exceeded" },
    });

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

  if (isSupabaseConfigured()) {
    try {
      const { createAdminClient } = await import("@/lib/supabase/server");
      const supabaseAdmin = createAdminClient();
      const body = await request.json();
      const parsed = registerSchema.safeParse(body);

      if (!parsed.success) {
        return NextResponse.json(
          {
            success: false,
            error:
              parsed.error.issues[0]?.message ||
              "Enter a valid name, email, password (min 8 chars), and role.",
          },
          { status: 400 }
        );
      }

      const normalizedEmail = parsed.data.email.trim().toLowerCase();
      const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
        email: normalizedEmail,
        password: parsed.data.password,
        email_confirm: true,
        user_metadata: {
          full_name: parsed.data.full_name,
          role: parsed.data.role,
        },
      });

      if (authError || !authData?.user) {
        await logAuditEvent({
          actorId: null,
          actorEmail: normalizedEmail,
          action: "register_failure",
          result: "denied",
          ipAddress,
          userAgent,
          details: { reason: authError?.message || "Registration failed" },
        });

        return NextResponse.json(
          { success: false, error: authError?.message || "Registration failed" },
          { status: 400 }
        );
      }

      await logAuditEvent({
        actorId: authData.user.id,
        actorEmail: normalizedEmail,
        action: "register",
        result: "allowed",
        ipAddress,
        userAgent,
        description: `New user ${normalizedEmail} registered with role ${parsed.data.role}`,
        targetResourceType: "user",
        targetResourceId: authData.user.id,
        details: {
          operation: "account_registration",
          assigned_role: parsed.data.role,
        },
      });

      return NextResponse.json(
        {
          success: true,
          message: "Account created successfully. Sign in to continue.",
          data: {
            user: {
              id: authData.user.id,
              email: normalizedEmail,
              full_name: parsed.data.full_name,
              role: parsed.data.role,
            },
          },
        },
        { status: 201 }
      );
    } catch (err: unknown) {
      console.error("[AUTH] Supabase registration error:", err);
      return NextResponse.json(
        { success: false, error: "Registration failed due to a server error." },
        { status: 500 }
      );
    }
  }

  try {
    const body = await request.json();
    const parsed = registerSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          success: false,
          error:
            parsed.error.issues[0]?.message ||
            "Enter a valid name, email, password (min 8 chars), and role.",
        },
        { status: 400 }
      );
    }

    const fullName = parsed.data.full_name;
    const normalizedEmail = parsed.data.email.trim().toLowerCase();
    const selectedRole = parsed.data.role;
    const passwordRecord = hashPassword(parsed.data.password);

    const ownerEmail = process.env.TRUSTVAULT_OWNER_EMAIL
      ?.trim()
      .toLowerCase();

    const result = await mutateStore((store) => {
      const emailExists = store.users.some(
        (user) => user.email.trim().toLowerCase() === normalizedEmail
      );

      if (emailExists) {
        return { error: "EXISTS" as const };
      }

      const now = new Date().toISOString();

      const user: User = {
        id: randomUUID(),
        email: normalizedEmail,
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
      await logAuditEvent({
        actorId: null,
        actorEmail: normalizedEmail,
        action: "register_failure",
        result: "denied",
        ipAddress,
        userAgent,
        details: {
          reason: "An account with this email already exists",
        },
      });

      return NextResponse.json(
        {
          success: false,
          error: "An account with this email already exists.",
        },
        { status: 409 }
      );
    }

    const isConfiguredOwner =
      Boolean(ownerEmail) && normalizedEmail === ownerEmail;

    await logAuditEvent({
      actorId: result.user.id,
      actorEmail: result.user.email,
      action: "register",
      result: "allowed",
      ipAddress,
      userAgent,
      description: `New user ${result.user.email} registered with role ${selectedRole}`,
      targetResourceType: "user",
      targetResourceId: result.user.id,
      details: {
        operation: "account_registration",
        assigned_role: selectedRole,
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
