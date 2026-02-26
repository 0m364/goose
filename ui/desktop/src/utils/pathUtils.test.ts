import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { expandTilde } from './pathUtils';
import os from 'node:os';
import path from 'node:path';

// Mock dependencies
vi.mock('node:os', () => ({
  default: {
    homedir: vi.fn(),
  },
}));

vi.mock('node:path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:path')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      join: vi.fn((...args) => actual.default.join(...args)),
    },
  };
});

describe('pathUtils', () => {
  const originalPlatform = process.platform;

  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    Object.defineProperty(process, 'platform', {
      value: originalPlatform,
    });
  });

  describe('expandTilde', () => {
    it('should return original value for invalid inputs', () => {
      // @ts-expect-error Testing invalid input
      expect(expandTilde(null)).toBe(null);
      // @ts-expect-error Testing invalid input
      expect(expandTilde(undefined)).toBe(undefined);
      // @ts-expect-error Testing invalid input
      expect(expandTilde(123)).toBe(123);
    });

    it('should return original value for empty string', () => {
      expect(expandTilde('')).toBe('');
    });

    it('should return original value for paths not starting with ~', () => {
      expect(expandTilde('/usr/bin')).toBe('/usr/bin');
      expect(expandTilde('relative/path')).toBe('relative/path');
    });

    describe('POSIX (Linux/macOS)', () => {
      beforeEach(() => {
        Object.defineProperty(process, 'platform', {
          value: 'linux',
        });
        (os.homedir as any).mockReturnValue('/home/user');
        // Use posix join implementation
        (path.join as any).mockImplementation((...args: string[]) => path.posix.join(...args));
      });

      it('should expand ~ to home directory', () => {
        expect(expandTilde('~')).toBe('/home/user');
      });

      it('should expand ~/path to home/path', () => {
        expect(expandTilde('~/documents/file.txt')).toBe('/home/user/documents/file.txt');
      });

      it('should use generic fallback for ~path (no separator)', () => {
        // Code: path.join(homedir, filePath.slice(1))
        // 'user2' -> join('/home/user', 'user2') -> '/home/user/user2'
        // This behavior implies ~user2 is treated as a relative path from current user's home,
        // which matches the implementation "generic fallback: replace only the first leading tilde".
        // Note: In bash, ~user2 expands to user2's home dir, but here the code implements generic replacement.
        expect(expandTilde('~user2/docs')).toBe('/home/user/user2/docs');
      });

      it('should handle backslash as generic fallback on POSIX', () => {
        // On POSIX, \ is a valid filename character, not a separator.
        // So ~\\foo is treated as a file starting with ~\.
        // The code: process.platform !== 'win32', so it falls to generic fallback.
        // path.join('/home/user', '\\foo') -> '/home/user/\\foo'
        expect(expandTilde('~\\foo')).toBe('/home/user/\\foo');
      });
    });

    describe('Windows', () => {
      beforeEach(() => {
        Object.defineProperty(process, 'platform', {
          value: 'win32',
        });
        (os.homedir as any).mockReturnValue('C:\\Users\\user');
        // Use win32 join implementation
        (path.join as any).mockImplementation((...args: string[]) => path.win32.join(...args));
      });

      it('should expand ~ to home directory', () => {
        expect(expandTilde('~')).toBe('C:\\Users\\user');
      });

      it('should expand ~\\path to home\\path', () => {
        expect(expandTilde('~\\Documents\\file.txt')).toBe('C:\\Users\\user\\Documents\\file.txt');
      });

      it('should expand ~/path to home\\path (forward slash supported)', () => {
        // Windows supports / in APIs, but path.join usually normalizes to \
        // expandTilde handles ~/ explicitly.
        expect(expandTilde('~/Documents/file.txt')).toBe('C:\\Users\\user\\Documents\\file.txt');
      });

      it('should use generic fallback for ~path', () => {
        expect(expandTilde('~user2\\docs')).toBe('C:\\Users\\user\\user2\\docs');
      });
    });
  });
});
