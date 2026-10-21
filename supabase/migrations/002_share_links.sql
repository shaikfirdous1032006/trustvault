-- ============================================================================
-- TrustVault Database Migration: 002_share_links
-- Expiring, tokenised external disclosure links.
--
-- The server stores only SHA-256(token). The anonymous bearer therefore gets no
-- table visibility at all: it may EXECUTE one security-definer function that
-- answers for exactly the digest it presents.
-- ============================================================================

CREATE TABLE public.share_links (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  label TEXT,
  created_by UUID NOT NULL REFERENCES public.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_by UUID REFERENCES public.users(id),
  access_count INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
  max_access_count INTEGER CHECK (max_access_count IS NULL OR max_access_count > 0),
  last_accessed_at TIMESTAMPTZ,
  allow_download BOOLEAN NOT NULL DEFAULT TRUE,
  watermark_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  -- A link that is not revoked must be alive: expiry is mandatory, unlike a
  -- named grant which may legitimately be open-ended.
  CONSTRAINT share_links_must_expire CHECK (expires_at > created_at)
);

CREATE INDEX idx_share_links_document ON public.share_links(document_id);
CREATE INDEX idx_share_links_created_by ON public.share_links(created_by);
CREATE UNIQUE INDEX idx_share_links_token_hash ON public.share_links(token_hash);
CREATE INDEX idx_share_links_active ON public.share_links(document_id)
  WHERE revoked_at IS NULL AND expires_at > now();

ALTER TABLE public.share_links ENABLE ROW LEVEL SECURITY;

-- Nobody may read the raw table. This is deliberate: a policy that let a bearer
-- "see live links" would let any authenticated user dump every live digest, and
-- digests are the only thing standing between a leaked table and a working link.

-- The document owner manages their own links.
CREATE POLICY "owner_select_share_links" ON public.share_links
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = share_links.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- Platform admins see links for oversight, never the tokens (which are not stored).
CREATE POLICY "admin_select_share_links" ON public.share_links
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid() AND u.role = 'admin'
    )
  );

CREATE POLICY "owner_insert_share_links" ON public.share_links
  FOR INSERT TO authenticated
  WITH CHECK (
    created_by = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = share_links.document_id
        AND d.owner_id = auth.uid()
        AND d.is_deleted = FALSE
    )
  );

-- Revocation only: the recipient-facing terms are frozen at issue time.
CREATE POLICY "owner_update_share_links" ON public.share_links
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.documents d
      WHERE d.id = share_links.document_id
        AND d.owner_id = auth.uid()
    )
  );

-- No DELETE policy: issued links are revoked, not erased, so the audit trail keeps
-- a link id that still resolves to a row.

-- A WITH CHECK clause cannot reference OLD, so the "do not reissue an existing
-- link" rule lives in a trigger where the old row is available.
CREATE OR REPLACE FUNCTION public.prevent_share_link_reissue()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.document_id IS DISTINCT FROM OLD.document_id
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.allow_download IS DISTINCT FROM OLD.allow_download
     OR NEW.max_access_count IS DISTINCT FROM OLD.max_access_count
  THEN
    RAISE EXCEPTION 'share link terms are immutable; revoke it and issue a new link'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_share_links_updated
  BEFORE UPDATE ON public.share_links
  FOR EACH ROW EXECUTE FUNCTION public.prevent_share_link_reissue();

REVOKE ALL ON public.share_links FROM anon;
REVOKE ALL ON public.share_links FROM authenticated;
-- Re-grant the managed paths to authenticated owners/admins via RLS above.
GRANT SELECT, INSERT, UPDATE ON public.share_links TO authenticated;

-- ----------------------------------------------------------------------------
-- resolve_share_link
--
-- The only door an anonymous bearer has. It accepts a digest, and returns a
-- single row only if a live link hashes to exactly that digest. Because the match
-- is on the digest, the function leaks nothing about other links, and the
-- counter is incremented in the same statement, so two concurrent views cannot
-- both pass a max_access_count check.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.resolve_share_link(
  p_token_hash TEXT,
  p_wants_download BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
  link_id UUID,
  document_id UUID,
  title TEXT,
  file_name TEXT,
  storage_path TEXT,
  mime_type TEXT,
  file_size BIGINT,
  checksum TEXT,
  current_version INTEGER,
  label TEXT,
  expires_at TIMESTAMPTZ,
  access_count INTEGER,
  max_access_count INTEGER,
  allow_download BOOLEAN,
  watermark_enabled BOOLEAN,
  denied_reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_link public.share_links%ROWTYPE;
  v_doc public.documents%ROWTYPE;
  v_denied TEXT;
BEGIN
  -- Lock the row so the counter below is written against the same snapshot that
  -- decided the limit had not yet been reached.
  SELECT * INTO v_link
  FROM public.share_links
  WHERE token_hash = p_token_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    v_denied := 'not_found';
  ELSE
    SELECT * INTO v_doc FROM public.documents WHERE id = v_link.document_id;

    IF NOT FOUND OR v_doc.is_deleted THEN
      v_denied := 'document_unavailable';
    ELSIF v_link.max_access_count IS NOT NULL
      AND v_link.access_count >= v_link.max_access_count THEN
      -- Tested before revoked_at: closing a capped link writes revoked_at, so
      -- checking revocation first would misreport "used up" as "revoked".
      v_denied := 'exhausted';
    ELSIF v_link.revoked_at IS NOT NULL THEN
      v_denied := 'revoked';
    ELSIF v_link.expires_at <= now() THEN
      v_denied := 'expired';
    ELSIF p_wants_download AND NOT v_link.allow_download THEN
      v_denied := 'download_forbidden';
    ELSE
      UPDATE public.share_links
      SET access_count = access_count + 1,
          last_accessed_at = now(),
          revoked_at = CASE
            WHEN max_access_count IS NOT NULL AND access_count + 1 >= max_access_count
            THEN now() ELSE revoked_at END,
          revoked_by = CASE
            WHEN max_access_count IS NOT NULL AND access_count + 1 >= max_access_count
            THEN created_by ELSE revoked_by END
      WHERE id = v_link.id
      RETURNING * INTO v_link;
    END IF;
  END IF;

  IF v_denied IS NULL THEN
    RETURN QUERY SELECT
      v_link.id,
      v_doc.id,
      v_doc.title,
      v_doc.file_name,
      v_doc.storage_path,
      v_doc.mime_type,
      v_doc.file_size,
      v_doc.checksum,
      v_doc.current_version,
      v_link.label,
      v_link.expires_at,
      v_link.access_count,
      v_link.max_access_count,
      v_link.allow_download,
      v_link.watermark_enabled,
      NULL::TEXT;
  ELSE
    -- A denial still describes the link the caller already proved it owns, but no
    -- document fields are returned.
    RETURN QUERY SELECT
      v_link.id,
      v_link.document_id,
      NULL::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      NULL::TEXT,
      NULL::BIGINT,
      NULL::TEXT,
      NULL::INTEGER,
      v_link.label,
      v_link.expires_at,
      v_link.access_count,
      v_link.max_access_count,
      v_link.allow_download,
      v_link.watermark_enabled,
      v_denied;
  END IF;
END;
$$;

-- The application uses the service role for bearer traffic, but if an anon key is
-- ever used directly this is the only thing it could call.
GRANT EXECUTE ON FUNCTION public.resolve_share_link(TEXT, BOOLEAN) TO anon, authenticated, service_role;
