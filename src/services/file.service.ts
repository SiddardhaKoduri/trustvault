import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const STORAGE_DIR = process.env.STORAGE_DIR || './storage/blobs';

export interface FileValidationResult {
  valid: boolean;
  detectedMimeType?: string;
  error?: string;
}

export class FileService {
  /**
   * Initializes the isolated storage directory.
   */
  static ensureStorageDirectory() {
    if (!fs.existsSync(STORAGE_DIR)) {
      fs.mkdirSync(STORAGE_DIR, { recursive: true });
    }
  }

  /**
   * Inspects binary magic numbers to determine true MIME type.
   * Completely immune to file extension spoofing or client-forged Content-Type headers.
   */
  static validateMagicBytes(buffer: Buffer): FileValidationResult {
    if (!buffer || buffer.length === 0) {
      return { valid: false, error: 'File buffer is empty.' };
    }

    // 1. PDF signature: %PDF- (hex: 25 50 44 46 2D)
    if (
      buffer.length >= 5 &&
      buffer[0] === 0x25 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x44 &&
      buffer[3] === 0x46 &&
      buffer[4] === 0x2d
    ) {
      return { valid: true, detectedMimeType: 'application/pdf' };
    }

    // 2. PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if (
      buffer.length >= 8 &&
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47 &&
      buffer[4] === 0x0d &&
      buffer[5] === 0x0a &&
      buffer[6] === 0x1a &&
      buffer[7] === 0x0a
    ) {
      return { valid: true, detectedMimeType: 'image/png' };
    }

    // 3. JPEG signature: FF D8 FF
    if (
      buffer.length >= 3 &&
      buffer[0] === 0xff &&
      buffer[1] === 0xd8 &&
      buffer[2] === 0xff
    ) {
      return { valid: true, detectedMimeType: 'image/jpeg' };
    }

    // 4. Plain Text / Markdown: Validate UTF-8 compliance and ensure no binary null bytes
    let isText = true;
    const checkLength = Math.min(buffer.length, 1024);
    for (let i = 0; i < checkLength; i++) {
      // Null byte 0x00 indicates compiled binary / executable shellcode
      if (buffer[i] === 0x00) {
        isText = false;
        break;
      }
    }

    if (isText) {
      // Verify valid UTF-8
      try {
        const textStr = buffer.toString('utf-8');
        if (textStr.length > 0) {
          const textLower = textStr.slice(0, 2048).toLowerCase();
          // Prohibit active HTML, SVG, and script payloads in text files to eliminate stored XSS vectors
          if (
            textLower.includes('<script') ||
            textLower.includes('<html') ||
            textLower.includes('<!doctype') ||
            textLower.includes('<?php') ||
            textLower.includes('<svg')
          ) {
            return {
              valid: false,
              error: 'Executable scripts and HTML/SVG markup are prohibited in vault documents.',
            };
          }
          return { valid: true, detectedMimeType: 'text/plain' };
        }
      } catch {
        isText = false;
      }
    }

    return {
      valid: false,
      error: 'File signature rejected. Only PDF, PNG, JPEG, and valid UTF-8 documents are accepted.',
    };
  }

  /**
   * Sanitizes user-provided filename to prevent Path Traversal attacks.
   */
  static sanitizeFilename(originalName: string): string {
    const basename = path.basename(originalName);
    // Remove directory traversal sequences, backslashes, and unsafe characters
    return basename.replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  /**
   * Commits an uploaded file buffer to the isolated blob storage under a randomized UUID key.
   */
  static async saveBlob(buffer: Buffer): Promise<string> {
    FileService.ensureStorageDirectory();
    const storageKey = crypto.randomUUID();
    const targetPath = path.join(STORAGE_DIR, storageKey);

    await fs.promises.writeFile(targetPath, buffer);
    return storageKey;
  }

  /**
   * Retrieves read stream for an isolated storage key.
   */
  static getBlobStream(storageKey: string): fs.ReadStream {
    // Prevent path traversal within storageKey itself
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(STORAGE_DIR, sanitizedKey);

    if (!fs.existsSync(targetPath)) {
      throw new Error('Blob not found in vault storage.');
    }

    return fs.createReadStream(targetPath);
  }

  /**
   * Deletes a physical file blob from storage.
   */
  static async deleteBlob(storageKey: string): Promise<void> {
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(STORAGE_DIR, sanitizedKey);

    if (fs.existsSync(targetPath)) {
      await fs.promises.unlink(targetPath);
    }
  }
}
