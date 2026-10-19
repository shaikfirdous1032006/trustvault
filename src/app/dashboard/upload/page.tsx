"use client";

import { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  Upload,
  FileText,
  X,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Shield,
} from "lucide-react";

const CATEGORIES = [
  { value: "general", label: "General" },
  { value: "legal", label: "Legal" },
  { value: "financial", label: "Financial" },
  { value: "technical", label: "Technical" },
  { value: "hr", label: "Human Resources" },
  { value: "marketing", label: "Marketing" },
  { value: "other", label: "Other" },
];

const ALLOWED_TYPES = [
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "text/plain",
  "text/csv",
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
];

const MAX_FILE_SIZE = 52428800; // 50MB

export default function UploadPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("general");
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  function validateFile(f: File): string | null {
    if (!ALLOWED_TYPES.includes(f.type)) {
      return `File type "${f.type}" is not allowed. Supported: PDF, Word, Excel, PowerPoint, text, CSV, and images.`;
    }
    if (f.size > MAX_FILE_SIZE) {
      return `File size (${formatFileSize(f.size)}) exceeds the 50MB limit.`;
    }
    return null;
  }

  function handleFile(f: File) {
    const validationError = validateFile(f);
    if (validationError) {
      setError(validationError);
      return;
    }
    setFile(f);
    setError("");
    if (!title) {
      setTitle(f.name.replace(/\.[^/.]+$/, ""));
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setUploading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("title", title);
      formData.append("description", description);
      formData.append("category", category);

      const res = await fetch("/api/documents", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Upload failed");
        return;
      }

      setSuccess(true);
      setTimeout(() => {
        router.push(`/dashboard/documents/${data.data.id}`);
      }, 1500);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setUploading(false);
    }
  }

  if (success) {
    return (
      <div className="max-w-2xl mx-auto animate-fade-in">
        <div className="card text-center py-12">
          <CheckCircle2 className="w-16 h-16 text-success mx-auto mb-4" />
          <h2 className="text-2xl font-bold mb-2">Upload Complete!</h2>
          <p className="text-[var(--muted)]">
            Your document has been securely uploaded and versioned.
          </p>
          <p className="text-sm text-[var(--muted)] mt-2">
            Redirecting to document page...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Upload className="w-6 h-6 text-brand-400" />
          Upload Document
        </h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          Upload a document to your secure vault
        </p>
      </div>

      {/* Security notice */}
      <div className="card-glass flex items-start gap-3 mb-6 p-4">
        <Shield className="w-5 h-5 text-brand-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-brand-300">Secure Upload</p>
          <p className="text-[var(--muted)] text-xs mt-0.5">
            Files are stored in a private bucket. SHA-256 checksum computed on
            upload. Access requires explicit permission grants.
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm flex items-center gap-2 animate-fade-in">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* File Drop Zone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`
            border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all
            ${
              dragOver
                ? "border-brand-500 bg-brand-500/10"
                : file
                ? "border-success/50 bg-success/5"
                : "border-[var(--input-border)] hover:border-brand-500/50 hover:bg-brand-500/5"
            }
          `}
          id="file-drop-zone"
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => {
              if (e.target.files?.[0]) handleFile(e.target.files[0]);
            }}
            accept={ALLOWED_TYPES.join(",")}
            className="hidden"
            id="file-input"
          />

          {file ? (
            <div className="flex items-center justify-center gap-3">
              <FileText className="w-8 h-8 text-success" />
              <div className="text-left">
                <p className="text-sm font-medium">{file.name}</p>
                <p className="text-xs text-[var(--muted)]">
                  {formatFileSize(file.size)} • {file.type}
                </p>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);
                }}
                className="btn btn-ghost btn-sm ml-2"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <>
              <Upload className="w-10 h-10 text-[var(--muted)] mx-auto mb-3 opacity-50" />
              <p className="text-sm font-medium">
                Drop your file here, or click to browse
              </p>
              <p className="text-xs text-[var(--muted)] mt-1">
                PDF, Word, Excel, PowerPoint, text, CSV, images • Max 50MB
              </p>
            </>
          )}
        </div>

        {/* Title */}
        <div>
          <label
            htmlFor="doc-title"
            className="block text-sm font-medium mb-1.5 text-[var(--muted)]"
          >
            Title *
          </label>
          <input
            id="doc-title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="input"
            placeholder="Document title"
            required
            maxLength={255}
          />
        </div>

        {/* Description */}
        <div>
          <label
            htmlFor="doc-description"
            className="block text-sm font-medium mb-1.5 text-[var(--muted)]"
          >
            Description
          </label>
          <textarea
            id="doc-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="input min-h-[80px] resize-y"
            placeholder="Optional description..."
            maxLength={1000}
          />
        </div>

        {/* Category */}
        <div>
          <label
            htmlFor="doc-category"
            className="block text-sm font-medium mb-1.5 text-[var(--muted)]"
          >
            Category *
          </label>
          <select
            id="doc-category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="input appearance-none cursor-pointer"
          >
            {CATEGORIES.map((cat) => (
              <option key={cat.value} value={cat.value}>
                {cat.label}
              </option>
            ))}
          </select>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={!file || !title || uploading}
          className="btn btn-primary w-full btn-lg"
          id="upload-submit-btn"
        >
          {uploading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Uploading securely...
            </>
          ) : (
            <>
              <Shield className="w-4 h-4" />
              Upload Document
            </>
          )}
        </button>
      </form>
    </div>
  );
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
