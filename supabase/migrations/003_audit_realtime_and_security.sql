-- ============================================================================
-- TrustVault Database Migration: 003_audit_realtime_and_security
-- 
-- 1. Enables Supabase Realtime publication for audit_events with full row replica identity.
-- 2. Hardens Row Level Security (RLS) on audit_events:
--    - Grants SELECT for users to read their own events (actor_id = auth.uid())
--    - Grants SELECT for users to read events for permitted documents
--    - Drops direct INSERT policy for authenticated users (inserts MUST go through server-side service role)
--    - Enforces append-only immutability (UPDATE and DELETE are revoked and blocked by triggers)
-- 3. Adds automated database trigger on public.users for role/status changes to prevent bypassing app-level audit.
-- ============================================================================

-- 1. EXTENSIONS & SUPABASE REALTIME CONFIGURATION
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Ensure audit_events table emits real-time INSERT notifications
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables 
      WHERE pubname = 'supabase_realtime' 
        AND schemaname = 'public' 
        AND tablename = 'audit_events'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.audit_events;
    END IF;
  END IF;
END $$;

-- Set replica identity to full so real-time subscribers receive all row fields
ALTER TABLE public.audit_events REPLICA IDENTITY FULL;

-- 2. ROW LEVEL SECURITY (RLS) HARDENING

-- Drop the permissive insert policy: ordinary users MUST NOT insert arbitrary audit records directly
DROP POLICY IF EXISTS "insert_audit" ON public.audit_events;

-- Document owners already have "owner_select_audit" from 001_initial_schema
-- Administrators already have "admin_select_audit" from 001_initial_schema

-- Users can inspect their own activity events
DROP POLICY IF EXISTS "users_select_own_audit" ON public.audit_events;
CREATE POLICY "users_select_own_audit" ON public.audit_events
  FOR SELECT TO authenticated
  USING (
    actor_id = auth.uid()
  );

-- Users can inspect audit events on documents where they have active access
DROP POLICY IF EXISTS "permitted_select_audit" ON public.audit_events;
CREATE POLICY "permitted_select_audit" ON public.audit_events
  FOR SELECT TO authenticated
  USING (
    document_id IS NOT NULL
    AND public.has_document_permission(auth.uid(), document_id, 'read')
  );

-- Explicitly revoke write permissions from authenticated and anon roles
REVOKE INSERT, UPDATE, DELETE ON public.audit_events FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.audit_events FROM anon;
GRANT SELECT ON public.audit_events TO authenticated;

-- 3. DATABASE TRIGGER FOR DIRECT DATABASE CHANGES
-- Detects direct administrative modifications to user accounts that might bypass application logic
CREATE OR REPLACE FUNCTION public.audit_user_changes_trigger()
RETURNS TRIGGER AS $$
DECLARE
  v_app_flag TEXT;
  v_prev_hash TEXT;
  v_event_hash TEXT;
  v_action TEXT;
  v_details JSONB;
BEGIN
  -- Prevent duplicate logging if the application already logged this event
  v_app_flag := current_setting('trustvault.app_audit', true);
  IF v_app_flag = 'true' THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.role IS DISTINCT FROM OLD.role THEN
      v_action := 'role_change';
      v_details := jsonb_build_object(
        'operation', 'role_change',
        'target_user_id', NEW.id,
        'target_user_email', NEW.email,
        'previous_role', OLD.role,
        'new_role', NEW.role,
        'source', 'database_trigger',
        'description', 'User ' || NEW.email || ' role changed from ' || OLD.role || ' to ' || NEW.role
      );
    ELSIF NEW.is_active IS DISTINCT FROM OLD.is_active THEN
      v_action := CASE WHEN NEW.is_active THEN 'account_activated' ELSE 'account_deactivated' END;
      v_details := jsonb_build_object(
        'operation', v_action,
        'target_user_id', NEW.id,
        'target_user_email', NEW.email,
        'is_active', NEW.is_active,
        'source', 'database_trigger',
        'description', 'User ' || NEW.email || ' account was ' || CASE WHEN NEW.is_active THEN 'activated' ELSE 'deactivated' END
      );
    ELSE
      RETURN NEW;
    END IF;

    -- Query latest hash pointer
    SELECT event_hash INTO v_prev_hash 
    FROM public.audit_events 
    ORDER BY occurred_at DESC 
    LIMIT 1;

    -- Compute SHA-256 hash using pgcrypto digest
    v_event_hash := encode(
      digest(
        now()::text || '|' || COALESCE(auth.uid()::text, '') || '||' || v_action || '|allowed|' || v_details::text || '|' || COALESCE(v_prev_hash, ''),
        'sha256'
      ),
      'hex'
    );

    INSERT INTO public.audit_events (
      occurred_at,
      actor_id,
      actor_email,
      action,
      result,
      details_jsonb,
      prev_hash,
      event_hash
    ) VALUES (
      now(),
      auth.uid(),
      (SELECT email FROM public.users WHERE id = auth.uid()),
      v_action,
      'allowed',
      v_details,
      v_prev_hash,
      v_event_hash
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_user_audit_change ON public.users;
CREATE TRIGGER on_user_audit_change
  AFTER UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.audit_user_changes_trigger();
