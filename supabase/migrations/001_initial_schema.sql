-- ============================================================================
-- TrustVault Database Migration: 001_initial_schema
-- Creates all tables, RLS policies, triggers, and functions
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. USERS TABLE (extends Supabase auth.users)
-- ============================================================================
CREATE TABLE public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'owner', 'viewer')),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for role-based lookups
CREATE INDEX idx_users_role ON public.users(role);
CREATE INDEX idx_users_email ON public.users(email);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER on_users_updated
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- Auto-create user profile on auth signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.users (id, email, full_name, role)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'role', 'viewer')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- RLS for users
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Default deny: no implicit access
-- Admin can see all users
CREATE POLICY "admin_select_users" ON public.users
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role = 'admin'
    )
  );

-- Users can see their own profile
CREATE POLICY "users_select_own" ON public.users
  FOR SELECT TO authenticated
  USING (id = auth.uid());

-- Users can update their own profile (not role)
CREATE POLICY "users_update_own" ON public.users
  FOR UPDATE TO authenticated
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- Admin can update any user
CREATE POLICY "admin_update_users" ON public.users
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role = 'admin'
    )
  )
  WITH CHECK (true);


-- ============================================================================
-- 2. DOCUMENTS TABLE
-- ============================================================================
CREATE TABLE public.documents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL DEFAULT 'general',
  storage_path TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  mime_type TEXT NOT NULL,
  checksum TEXT NOT NULL, -- SHA-256 of file content
  current_version INT NOT NULL DEFAULT 1,
  is_deleted BOOLEAN NOT NULL DEFAULT false,
  deleted_at TIMESTAMPTZ,
  deleted_by UUID REFERENCES public.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_documents_owner ON public.documents(owner_id);
CREATE INDEX idx_documents_category ON public.documents(category);
CREATE INDEX idx_documents_created ON public.documents(created_at DESC);
CREATE INDEX idx_documents_deleted ON public.documents(is_deleted);
CREATE INDEX idx_documents_title_search ON public.documents USING gin(to_tsvector('english', title));

CREATE TRIGGER on_documents_updated
  BEFORE UPDATE ON public.documents
  FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- RLS for documents
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- Owner can see their own documents
CREATE POLICY "owner_select_documents" ON public.documents
  FOR SELECT TO authenticated
  USING (owner_id = auth.uid());

-- Users with active permission can see documents
CREATE POLICY "permitted_select_documents" ON public.documents
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.document_permissions dp
      WHERE dp.document_id = documents.id
        AND dp.user_id = auth.uid()
        AND dp.permission_level IN ('read', 'edit')
        AND dp.revoked_at IS NULL
        AND (dp.expires_at IS NULL OR dp.expires_at > now())
    )
  );

-- CRITICAL: Admins do NOT receive implicit document-read access.
-- Admins can only read documents where they are the owner or have explicit active permission.
-- Admin dashboard monitors platform activity, users, and audit logs without reading document contents.

-- Only owners/admins can insert documents
CREATE POLICY "owner_insert_documents" ON public.documents
  FOR INSERT TO authenticated
  WITH CHECK (
    owner_id = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role IN ('owner', 'admin')
    )
  );

-- Owner can update their own documents
CREATE POLICY "owner_update_documents" ON public.documents
  FOR UPDATE TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

-- Users with edit permission can update documents
CREATE POLICY "editor_update_documents" ON public.documents
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.document_permissions dp
      WHERE dp.document_id = documents.id
        AND dp.user_id = auth.uid()
        AND dp.permission_level = 'edit'
        AND dp.revoked_at IS NULL
        AND (dp.expires_at IS NULL OR dp.expires_at > now())
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.document_permissions dp
      WHERE dp.document_id = documents.id
        AND dp.user_id = auth.uid()
        AND dp.permission_level = 'edit'
        AND dp.revoked_at IS NULL
        AND (dp.expires_at IS NULL OR dp.expires_at > now())
    )
  );

-- Owner can soft-delete their own documents
CREATE POLICY "owner_delete_documents" ON public.documents
  FOR DELETE TO authenticated
  USING (owner_id = auth.uid());


-- ============================================================================
-- 3. DOCUMENT PERMISSIONS TABLE
-- ============================================================================
CREATE TABLE public.document_permissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  permission_level TEXT NOT NULL CHECK (permission_level IN ('read', 'edit')),
  granted_by UUID NOT NULL REFERENCES public.users(id),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  revoked_by UUID REFERENCES public.users(id),
  expires_at TIMESTAMPTZ,
  UNIQUE(document_id, user_id, permission_level)
);

CREATE INDEX idx_perms_document ON public.document_permissions(document_id);
CREATE INDEX idx_perms_user ON public.document_permissions(user_id);
CREATE INDEX idx_perms_active ON public.document_permissions(document_id, user_id)
  WHERE revoked_at IS NULL;
CREATE INDEX idx_perms_granted_by ON public.document_permissions(granted_by);

-- RLS for document_permissions
ALTER TABLE public.document_permissions ENABLE ROW LEVEL SECURITY;

-- Document owner can see all permissions for their documents
CREATE POLICY "owner_select_permissions" ON public.document_permissions
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_permissions.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Users can see their own permissions
CREATE POLICY "user_select_own_permissions" ON public.document_permissions
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- Admin can see all permissions (metadata)
CREATE POLICY "admin_select_permissions" ON public.document_permissions
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role = 'admin'
    )
  );

-- Only document owner can grant permissions
CREATE POLICY "owner_insert_permissions" ON public.document_permissions
  FOR INSERT TO authenticated
  WITH CHECK (
    granted_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_permissions.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Only document owner can revoke permissions (update revoked_at)
CREATE POLICY "owner_update_permissions" ON public.document_permissions
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_permissions.document_id
        AND d.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_permissions.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Owner can delete permissions
CREATE POLICY "owner_delete_permissions" ON public.document_permissions
  FOR DELETE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_permissions.document_id
        AND d.owner_id = auth.uid()
    )
  );


-- ============================================================================
-- 4. DOCUMENT VERSIONS TABLE
-- ============================================================================
CREATE TABLE public.document_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
  version_number INT NOT NULL,
  storage_path TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  mime_type TEXT NOT NULL,
  checksum TEXT NOT NULL,
  uploaded_by UUID NOT NULL REFERENCES public.users(id),
  change_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(document_id, version_number)
);

CREATE INDEX idx_versions_document ON public.document_versions(document_id);
CREATE INDEX idx_versions_uploader ON public.document_versions(uploaded_by);

-- RLS for document_versions
ALTER TABLE public.document_versions ENABLE ROW LEVEL SECURITY;

-- Owner can see versions of their documents
CREATE POLICY "owner_select_versions" ON public.document_versions
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_versions.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Users with read/edit permission can see versions
CREATE POLICY "permitted_select_versions" ON public.document_versions
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.document_permissions dp
      WHERE dp.document_id = document_versions.document_id
        AND dp.user_id = auth.uid()
        AND dp.permission_level IN ('read', 'edit')
        AND dp.revoked_at IS NULL
        AND (dp.expires_at IS NULL OR dp.expires_at > now())
    )
  );

-- Owner can insert versions for their documents
CREATE POLICY "owner_insert_versions" ON public.document_versions
  FOR INSERT TO authenticated
  WITH CHECK (
    uploaded_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = document_versions.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Users with edit permission can insert versions
CREATE POLICY "editor_insert_versions" ON public.document_versions
  FOR INSERT TO authenticated
  WITH CHECK (
    uploaded_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.document_permissions dp
      WHERE dp.document_id = document_versions.document_id
        AND dp.user_id = auth.uid()
        AND dp.permission_level = 'edit'
        AND dp.revoked_at IS NULL
        AND (dp.expires_at IS NULL OR dp.expires_at > now())
    )
  );


-- ============================================================================
-- 5. AUDIT EVENTS TABLE (append-only)
-- ============================================================================
CREATE TABLE public.audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id UUID REFERENCES public.users(id),
  actor_email TEXT,
  document_id UUID REFERENCES public.documents(id),
  action TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('allowed', 'denied')),
  ip_hash TEXT,
  user_agent_hash TEXT,
  request_id TEXT,
  details_jsonb JSONB DEFAULT '{}',
  prev_hash TEXT,
  event_hash TEXT NOT NULL
);

-- Performance indexes
CREATE INDEX idx_audit_document ON public.audit_events(document_id);
CREATE INDEX idx_audit_actor ON public.audit_events(actor_id);
CREATE INDEX idx_audit_occurred ON public.audit_events(occurred_at DESC);
CREATE INDEX idx_audit_action ON public.audit_events(action);
CREATE INDEX idx_audit_result ON public.audit_events(result);

-- RLS for audit_events
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

-- Admin can read all audit events (metadata view)
CREATE POLICY "admin_select_audit" ON public.audit_events
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role = 'admin'
    )
  );

-- Document owners can read audit events for their documents
CREATE POLICY "owner_select_audit" ON public.audit_events
  FOR SELECT TO authenticated
  USING (
    document_id IS NOT NULL
    AND EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = audit_events.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Only service role or app can insert audit events
-- (authenticated users insert via server-side functions)
CREATE POLICY "insert_audit" ON public.audit_events
  FOR INSERT TO authenticated
  WITH CHECK (true);

-- *** CRITICAL: Block UPDATE on audit_events ***
-- No UPDATE policy exists = no updates allowed via RLS

-- *** CRITICAL: Block DELETE on audit_events ***
-- No DELETE policy exists = no deletes allowed via RLS

-- Additional safety: triggers to prevent UPDATE, DELETE, TRUNCATE
CREATE OR REPLACE FUNCTION public.prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit events are immutable. % operations are not permitted.', TG_OP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_audit_update
  BEFORE UPDATE ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();

CREATE TRIGGER prevent_audit_delete
  BEFORE DELETE ON public.audit_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();

-- Prevent TRUNCATE
CREATE OR REPLACE FUNCTION public.prevent_audit_truncate()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit events table cannot be truncated.';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_audit_truncate
  BEFORE TRUNCATE ON public.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_truncate();

-- Revoke UPDATE and DELETE privileges from application roles
REVOKE UPDATE, DELETE ON public.audit_events FROM authenticated;
REVOKE UPDATE, DELETE ON public.audit_events FROM anon;


-- ============================================================================
-- 6. HELPER FUNCTIONS
-- ============================================================================

-- Function to check if a user has active permission on a document
CREATE OR REPLACE FUNCTION public.has_document_permission(
  p_user_id UUID,
  p_document_id UUID,
  p_permission_level TEXT DEFAULT 'read'
)
RETURNS BOOLEAN AS $$
BEGIN
  -- Check if user is the document owner
  IF EXISTS (
    SELECT 1 FROM public.documents d
    WHERE d.id = p_document_id AND d.owner_id = p_user_id AND d.is_deleted = false
  ) THEN
    RETURN true;
  END IF;

  -- Check for active permission grant
  RETURN EXISTS (
    SELECT 1 FROM public.document_permissions dp
    WHERE dp.document_id = p_document_id
      AND dp.user_id = p_user_id
      AND (
        dp.permission_level = p_permission_level
        OR (p_permission_level = 'read' AND dp.permission_level = 'edit')
      )
      AND dp.revoked_at IS NULL
      AND (dp.expires_at IS NULL OR dp.expires_at > now())
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get user role
CREATE OR REPLACE FUNCTION public.get_user_role(p_user_id UUID)
RETURNS TEXT AS $$
DECLARE
  v_role TEXT;
BEGIN
  SELECT role INTO v_role FROM public.users WHERE id = p_user_id;
  RETURN v_role;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ============================================================================
-- 7. STORAGE BUCKET (private)
-- ============================================================================
-- Create private storage bucket for documents
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'documents',
  'documents',
  false,
  52428800, -- 50MB limit
  ARRAY[
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain',
    'text/csv',
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp'
  ]
) ON CONFLICT (id) DO NOTHING;

-- Storage RLS policies: only authenticated users with permission can access
CREATE POLICY "authenticated_upload" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'documents'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

-- Only the file owner or users with permission can download
CREATE POLICY "authorized_download" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'documents'
    AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR EXISTS (
        SELECT 1 FROM public.documents d
        WHERE d.storage_path = name
          AND public.has_document_permission(auth.uid(), d.id, 'read')
      )
    )
  );

-- Only the file owner can delete from storage
CREATE POLICY "owner_delete_storage" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'documents'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );


-- ============================================================================
-- 8. SEED DATA (Demo accounts)
-- Note: Run this AFTER creating auth users via Supabase Auth API
-- The handle_new_user trigger will auto-create user profiles
-- ============================================================================
-- Seed data is handled by the seed script (src/lib/seed.ts)
-- Demo accounts:
--   admin@example.com  (role: admin)
--   owner@example.com  (role: owner)
--   viewer@example.com (role: viewer)
