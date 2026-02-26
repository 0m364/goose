import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { expandTilde } from './pathUtils';
import path from 'node:path';
import os from 'node:os';

// Save original platform
const originalPlatform = process.platform;

vi.mock('node:os', async () => {
  return {
    default: {
      homedir: vi.fn(),
    },
  };
});

vi.mock('node:path', async () => {
  const actual = await vi.importActual<typeof import('node:path')>('node:path');
  return {
    default: {
      ...actual,
      join: vi.fn(),
    },
  };
});

describe('pathUtils', () => {
  describe('expandTilde', () => {
    beforeEach(() => {
      vi.resetAllMocks();
    });

    afterEach(() => {
      Object.defineProperty(process, 'platform', {
        value: originalPlatform,
      });
    });

    describe('Basic validation', () => {
      it('returns original value for null/undefined/empty/non-string', () => {
        // @ts-expect-error Testing invalid input
        expect(expandTilde(null)).toBe(null);
        // @ts-expect-error Testing invalid input
        expect(expandTilde(undefined)).toBe(undefined);
        expect(expandTilde('')).toBe('');
        // @ts-expect-error Testing invalid input
        expect(expandTilde(123)).toBe(123);
      });

      it('returns original path if it does not start with tilde', () => {
        const p = '/some/path';
        expect(expandTilde(p)).toBe(p);
      });
    });

    describe('POSIX (Linux/macOS)', () => {
      beforeEach(() => {
        Object.defineProperty(process, 'platform', {
          value: 'linux',
        });
        vi.mocked(os.homedir).mockReturnValue('/home/user');
        vi.mocked(path.join).mockImplementation((...args) => args.join('/'));
      });

      it('expands ~ to home dir', () => {
        expect(expandTilde('~')).toBe('/home/user');
      });

      it('expands ~/path to home/path', () => {
        expect(expandTilde('~/foo/bar')).toBe('/home/user/foo/bar');
        expect(path.join).toHaveBeenCalledWith('/home/user', 'foo/bar');
      });

      it('expands ~path using generic fallback', () => {
        // Code: if (filePath.startsWith('~')) -> path.join(homedir, filePath.slice(1))
        expect(expandTilde('~foo/bar')).toBe('/home/user/foo/bar');
        expect(path.join).toHaveBeenCalledWith('/home/user', 'foo/bar');
      });

      it('does NOT treat backslash specially on POSIX', () => {
        // Code checks `filePath.startsWith('~/')` or (win32 && `~\\`).
        // If POSIX, `~\\foo` fails the first check.
        // Falls into generic `~` check.
        // calls path.join(homedir, '\\foo') -> /home/user/\foo
        expect(expandTilde('~\\foo')).toBe('/home/user/\\foo');
        expect(path.join).toHaveBeenCalledWith('/home/user', '\\foo');
      });
    });

    describe('Windows', () => {
      beforeEach(() => {
        Object.defineProperty(process, 'platform', {
          value: 'win32',
        });
        vi.mocked(os.homedir).mockReturnValue('C:\\Users\\user');
        // Simple windows join mock
        vi.mocked(path.join).mockImplementation((...args) => args.join('\\'));
      });

      it('expands ~ to home dir', () => {
        expect(expandTilde('~')).toBe('C:\\Users\\user');
      });

      it('expands ~\\path to home\\path', () => {
        expect(expandTilde('~\\foo\\bar')).toBe('C:\\Users\\user\\foo\\bar');
        // slice(2) removes `~\` leaving `foo\bar`
        expect(path.join).toHaveBeenCalledWith('C:\\Users\\user', 'foo\\bar');
      });

      it('expands ~/path to home\\path (mixed usage)', () => {
        // `~/` works on Windows too in the code
        expect(expandTilde('~/foo/bar')).toBe('C:\\Users\\user\\foo/bar');
        // slice(2) removes `~/` leaving `foo/bar`
        // join('C:\Users\user', 'foo/bar') -> 'C:\Users\user\foo/bar'
        expect(path.join).toHaveBeenCalledWith('C:\\Users\\user', 'foo/bar');
      });

      it('expands ~path using generic fallback', () => {
        expect(expandTilde('~foo\\bar')).toBe('C:\\Users\\user\\foo\\bar');
        expect(path.join).toHaveBeenCalledWith('C:\\Users\\user', 'foo\\bar');
      });
    });
  });
});
