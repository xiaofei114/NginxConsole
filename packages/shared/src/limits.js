export const LIMITS = Object.freeze({
  maxPathBytes: 1024,
  maxPathSegmentBytes: 255,
  maxFileBytes: 512 * 1024,
  maxRequestBodyBytes: 1024 * 1024,
  maxCertificateBytes: 256 * 1024,
  maxArchiveBytes: 512 * 1024,
  maxArchiveBase64Chars: Math.ceil((512 * 1024) / 3) * 4,
  maxArchiveEntries: 64,
  maxArchiveFileBytes: 256 * 1024,
  maxArchiveTotalBytes: 512 * 1024,
  maxArchiveExpandedBytes: 8 * 1024 * 1024,
  maxListEntries: 500,
  maxBackups: 100,
  maxChainCertificates: 10,
  maxWsMessageBytes: 2 * 1024 * 1024,
  maxConcurrentCommands: 16,
  maxCommandOutputBytes: 64 * 1024,
  maxAuditReadBytes: 2 * 1024 * 1024,
});

export const DEFAULT_TEXT_EXTENSIONS = Object.freeze([
  '.conf', '.inc', '.txt', '.crt', '.cer', '.pem', '.csr', '.dhparam', '.template',
]);

export const CERT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export const SESSION_IDLE_TTL_MS = 60 * 60 * 1000;
export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;
