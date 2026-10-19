"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  FileText,
  Search,
  Filter,
  Upload,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Trash2,
  Calendar,
  User,
} from "lucide-react";

interface DocOwner {
  id: string;
  email: string;
  full_name: string | null;
}

interface Document {
  id: string;
  title: string;
  description: string | null;
  category: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  current_version: number;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
  owner: DocOwner;
}

const CATEGORIES = [
  "all",
  "general",
  "legal",
  "financial",
  "technical",
  "hr",
  "marketing",
  "other",
];

export default function DocumentsPage() {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 12;

  const fetchDocuments = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (category !== "all") params.set("category", category);
      params.set("page", page.toString());
      params.set("pageSize", pageSize.toString());

      const res = await fetch(`/api/documents?${params}`);
      const data = await res.json();
      if (data.success) {
        setDocuments(data.data);
        setTotal(data.total);
      }
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, [search, category, page]);

  useEffect(() => {
    fetchDocuments();
  }, [fetchDocuments]);

  // Debounce search
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="max-w-7xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileText className="w-6 h-6 text-brand-400" />
            Documents
          </h1>
          <p className="text-[var(--muted)] text-sm mt-1">
            Browse and manage your secure documents
          </p>
        </div>
        <Link href="/dashboard/upload" className="btn btn-primary" id="upload-document-btn">
          <Upload className="w-4 h-4" /> Upload
        </Link>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search documents..."
            className="input pl-10"
            id="search-documents-input"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
          <select
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setPage(1);
            }}
            className="input pl-10 pr-8 appearance-none cursor-pointer min-w-[160px]"
            id="category-filter-select"
          >
            {CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat === "all" ? "All Categories" : cat.charAt(0).toUpperCase() + cat.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Documents Grid */}
      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="card space-y-3">
              <div className="skeleton h-5 w-3/4" />
              <div className="skeleton h-3 w-full" />
              <div className="skeleton h-3 w-1/2" />
              <div className="flex gap-2 mt-3">
                <div className="skeleton h-5 w-16 rounded-full" />
                <div className="skeleton h-5 w-20 rounded-full" />
              </div>
            </div>
          ))}
        </div>
      ) : documents.length > 0 ? (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {documents.map((doc, i) => (
              <Link
                key={doc.id}
                href={`/dashboard/documents/${doc.id}`}
                className="card group cursor-pointer"
                style={{ animationDelay: `${i * 30}ms` }}
                id={`document-card-${doc.id}`}
              >
                <div className="flex items-start gap-3 mb-3">
                  <div className="w-10 h-10 rounded-lg bg-brand-600/15 flex items-center justify-center flex-shrink-0 group-hover:bg-brand-600/25 transition-colors">
                    <FileIcon mimeType={doc.mime_type} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold truncate group-hover:text-brand-400 transition-colors">
                      {doc.title}
                    </h3>
                    <p className="text-xs text-[var(--muted)] truncate">
                      {doc.file_name}
                    </p>
                  </div>
                </div>

                {doc.description && (
                  <p className="text-xs text-[var(--muted)] line-clamp-2 mb-3">
                    {doc.description}
                  </p>
                )}

                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="badge badge-brand">{doc.category}</span>
                  <span className="badge badge-neutral">
                    v{doc.current_version}
                  </span>
                  <span className="badge badge-neutral">
                    {formatFileSize(doc.file_size)}
                  </span>
                </div>

                <div className="flex items-center gap-3 mt-3 pt-3 border-t border-[var(--card-border)] text-xs text-[var(--muted)]">
                  <span className="flex items-center gap-1">
                    <User className="w-3 h-3" />
                    {doc.owner?.full_name || doc.owner?.email?.split("@")[0]}
                  </span>
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    {new Date(doc.created_at).toLocaleDateString()}
                  </span>
                </div>
              </Link>
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-6">
              <p className="text-sm text-[var(--muted)]">
                Showing {(page - 1) * pageSize + 1}–
                {Math.min(page * pageSize, total)} of {total}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1}
                  className="btn btn-secondary btn-sm"
                >
                  <ChevronLeft className="w-4 h-4" /> Prev
                </button>
                <span className="text-sm">
                  {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={page >= totalPages}
                  className="btn btn-secondary btn-sm"
                >
                  Next <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="empty-state py-16">
          {search || category !== "all" ? (
            <>
              <Search className="w-12 h-12 text-[var(--muted)] opacity-30" />
              <p className="text-lg font-medium mt-3">No documents found</p>
              <p className="text-sm text-[var(--muted)] mt-1">
                Try adjusting your search or filters
              </p>
              <button
                onClick={() => {
                  setSearchInput("");
                  setSearch("");
                  setCategory("all");
                }}
                className="btn btn-secondary btn-sm mt-4"
              >
                Clear filters
              </button>
            </>
          ) : (
            <>
              <FileText className="w-12 h-12 text-[var(--muted)] opacity-30" />
              <p className="text-lg font-medium mt-3">No documents yet</p>
              <p className="text-sm text-[var(--muted)] mt-1">
                Upload your first document to get started
              </p>
              <Link
                href="/dashboard/upload"
                className="btn btn-primary btn-sm mt-4"
              >
                <Upload className="w-4 h-4" /> Upload Document
              </Link>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function FileIcon({ mimeType }: { mimeType: string }) {
  if (mimeType.startsWith("image/")) {
    return <FileText className="w-5 h-5 text-brand-400" />;
  }
  if (mimeType === "application/pdf") {
    return <FileText className="w-5 h-5 text-red-400" />;
  }
  if (mimeType.includes("spreadsheet") || mimeType.includes("excel")) {
    return <FileText className="w-5 h-5 text-green-400" />;
  }
  return <FileText className="w-5 h-5 text-brand-400" />;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
