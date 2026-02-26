import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import os from 'node:os';
import { expandTilde } from './pathUtils';

// Mock os.homedir
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      homedir: vi.fn(),
    },
    homedir: vi.fn(),
  };
});

// We need to mock path to control join behavior for cross-platform testing
// Since the source imports 'node:path' as default, we need to mock that.
vi.mock('node:path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:path')>();
  return {
    ...actual,
    default: {
      ...actual,
      join: vi.fn(),
    },
    // Also mock named export if used (though source uses default)
    join: vi.fn(),
  };
});

describe('expandTilde', () => {
  const originalPlatform = process.platform;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    Object.defineProperty(process, 'platform', {
      value: originalPlatform,
    });
  });

  describe('Common behavior', () => {
    it('should return the input if it is not a string', () => {
      expect(expandTilde(null as any)).toBe(null);
      expect(expandTilde(undefined as any)).toBe(undefined);
      expect(expandTilde(123 as any)).toBe(123);
    });

    it('should return the input if it is an empty string', () => {
      expect(expandTilde('')).toBe('');
    });

    it('should return the input if it does not start with ~', () => {
      const filePath = '/usr/local/bin';
      expect(expandTilde(filePath)).toBe(filePath);
    });
  });

  describe('POSIX (Linux/macOS)', () => {
    beforeEach(async () => {
      Object.defineProperty(process, 'platform', {
        value: 'linux',
      });
      // Mock homedir
      vi.mocked(os.homedir).mockReturnValue('/home/user');

      // Mock path.join to behave like POSIX
      const originalPath = await vi.importActual<typeof import('node:path')>('node:path');
      vi.mocked(path.join).mockImplementation(originalPath.posix.join);
    });

    it('should expand "~" to user home directory', () => {
      expect(expandTilde('~')).toBe('/home/user');
    });

    it('should expand "~/path" to "home/path"', () => {
      expect(expandTilde('~/documents')).toBe('/home/user/documents');
    });

    it('should expand "~path" (generic fallback) correctly', () => {
      // Logic: return path.join(os.homedir(), filePath.slice(1));
      // ~documents -> /home/user/documents
      expect(expandTilde('~documents')).toBe('/home/user/documents');
    });

    it('should NOT treat "~\\" as a separator prefix on POSIX', () => {
      // On POSIX, \ is a valid filename character, so "~\foo" is "~" followed by "\foo"
      // The code:
      // if (filePath.startsWith('~/') || (process.platform === 'win32' && filePath.startsWith('~\\')))
      // It fails this check.
      // Falls through to generic check: if (filePath.startsWith('~'))
      // returns path.join(homedir, filePath.slice(1)) -> path.join('/home/user', '\foo')
      // posix.join('/home/user', '\foo') -> '/home/user/\foo'
      expect(expandTilde('~\\foo')).toBe('/home/user/\\foo');
    });
  });

  describe('Windows', () => {
    beforeEach(async () => {
      Object.defineProperty(process, 'platform', {
        value: 'win32',
      });
      // Mock homedir
      vi.mocked(os.homedir).mockReturnValue('C:\\Users\\user');

      // Mock path.join to behave like Windows
      const originalPath = await vi.importActual<typeof import('node:path')>('node:path');
      vi.mocked(path.join).mockImplementation(originalPath.win32.join);
    });

    it('should expand "~" to user home directory', () => {
      expect(expandTilde('~')).toBe('C:\\Users\\user');
    });

    it('should expand "~\\path" to "home\\path"', () => {
      expect(expandTilde('~\\documents')).toBe('C:\\Users\\user\\documents');
    });

    it('should expand "~/path" to "home\\path" (forward slash support)', () => {
      // filePath.startsWith('~/') is true.
      // remainder = 'documents'
      // path.join('C:\Users\user', 'documents') -> 'C:\Users\user\documents'
      expect(expandTilde('~/documents')).toBe('C:\\Users\\user\\documents');
    });

    it('should expand "~path" (generic fallback)', () => {
      expect(expandTilde('~documents')).toBe('C:\\Users\\user\\documents');
    });
  });
});
