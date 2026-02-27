import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createExtensionRecoverHints,
  formatExtensionErrorMessage,
  showExtensionLoadResults,
  MAX_ERROR_MESSAGE_LENGTH,
} from './extensionErrorUtils';
import { toastService } from '../toasts';

// Mock the toasts module
vi.mock('../toasts', () => ({
  toastService: {
    error: vi.fn(),
    extensionLoading: vi.fn(),
  },
}));

describe('extensionErrorUtils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createExtensionRecoverHints', () => {
    it('should include the error message in the hint', () => {
      const errorMsg = 'Network Error';
      const hints = createExtensionRecoverHints(errorMsg);
      expect(hints).toContain(errorMsg);
    });

    it('should include the standard hint text', () => {
      const errorMsg = 'Some error';
      const hints = createExtensionRecoverHints(errorMsg);
      expect(hints).toContain('Explain the following error:');
      expect(hints).toContain('This happened while trying to install an extension.');
      expect(hints).toContain('VPNs like WARP often cause issues.');
    });
  });

  describe('formatExtensionErrorMessage', () => {
    it('should return the original message if it is shorter than MAX_ERROR_MESSAGE_LENGTH', () => {
      const shortError = 'Short error';
      expect(shortError.length).toBeLessThan(MAX_ERROR_MESSAGE_LENGTH);
      const result = formatExtensionErrorMessage(shortError);
      expect(result).toBe(shortError);
    });

    it('should return the fallback message if the error is longer than MAX_ERROR_MESSAGE_LENGTH', () => {
      const longError = 'A'.repeat(MAX_ERROR_MESSAGE_LENGTH + 1);
      const fallback = 'Fallback message';
      const result = formatExtensionErrorMessage(longError, fallback);
      expect(result).toBe(fallback);
    });

    it('should use the default fallback if none is provided', () => {
      const longError = 'A'.repeat(MAX_ERROR_MESSAGE_LENGTH + 1);
      const result = formatExtensionErrorMessage(longError);
      expect(result).toBe('Failed to add extension');
    });

    it('should handle exactly MAX_ERROR_MESSAGE_LENGTH', () => {
      const edgeCaseError = 'A'.repeat(MAX_ERROR_MESSAGE_LENGTH);
      // The implementation is `errorMsg.length < MAX_ERROR_MESSAGE_LENGTH ? errorMsg : fallback`
      // So if length is EQUAL, it returns fallback.
      const result = formatExtensionErrorMessage(edgeCaseError);
      expect(result).toBe('Failed to add extension');
    });
  });

  describe('showExtensionLoadResults', () => {
    it('should do nothing if results are null or undefined or empty', () => {
      showExtensionLoadResults(null);
      expect(toastService.error).not.toHaveBeenCalled();
      expect(toastService.extensionLoading).not.toHaveBeenCalled();

      showExtensionLoadResults(undefined);
      expect(toastService.error).not.toHaveBeenCalled();
      expect(toastService.extensionLoading).not.toHaveBeenCalled();

      showExtensionLoadResults([]);
      expect(toastService.error).not.toHaveBeenCalled();
      expect(toastService.extensionLoading).not.toHaveBeenCalled();
    });

    it('should show a single error toast if there is one result and it failed', () => {
      const results = [{ name: 'ext1', success: false, error: 'Failed' }];
      showExtensionLoadResults(results);

      expect(toastService.error).toHaveBeenCalledWith({
        title: 'ext1',
        msg: 'Failed',
        traceback: 'Failed',
        recoverHints: expect.stringContaining('Failed'),
      });
      expect(toastService.extensionLoading).not.toHaveBeenCalled();
    });

    it('should use fallback message for long error in single error toast', () => {
        const longError = 'A'.repeat(MAX_ERROR_MESSAGE_LENGTH + 1);
        const results = [{ name: 'ext1', success: false, error: longError }];
        showExtensionLoadResults(results);

        expect(toastService.error).toHaveBeenCalledWith({
          title: 'ext1',
          msg: 'Failed to load extension',
          traceback: longError,
          recoverHints: expect.stringContaining(longError),
        });
      });

    it('should show extensionLoading toast if there are multiple results', () => {
      const results = [
        { name: 'ext1', success: true },
        { name: 'ext2', success: false, error: 'Failed' },
      ];
      showExtensionLoadResults(results);

      expect(toastService.extensionLoading).toHaveBeenCalledWith(
        [
          { name: 'ext1', status: 'success', error: undefined, recoverHints: undefined },
          {
            name: 'ext2',
            status: 'error',
            error: 'Failed',
            recoverHints: expect.stringContaining('Failed'),
          },
        ],
        2,
        true
      );
      expect(toastService.error).not.toHaveBeenCalled();
    });

    it('should show extensionLoading toast if there is a single success result', () => {
        const results = [{ name: 'ext1', success: true }];
        showExtensionLoadResults(results);

        expect(toastService.extensionLoading).toHaveBeenCalledWith(
          [{ name: 'ext1', status: 'success', error: undefined, recoverHints: undefined }],
          1,
          true
        );
        expect(toastService.error).not.toHaveBeenCalled();
      });
  });
});
