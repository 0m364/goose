import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatMessageTimestamp } from './timeUtils';

describe('timeUtils', () => {
  describe('formatMessageTimestamp', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      // Set a fixed date: January 15, 2024, 12:00:00 local time (conceptually)
      // Actually, we'll just pick a timestamp and let the system timezone do its thing.
      // Let's use a fixed timestamp for "now".
      const now = new Date('2024-01-15T12:00:00');
      vi.setSystemTime(now);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should format message from today with only time', () => {
      const now = new Date();
      // 1 hour ago
      const timestampDate = new Date(now.getTime() - 60 * 60 * 1000);
      const timestamp = timestampDate.getTime() / 1000;

      const expectedTimeStr = timestampDate.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      expect(formatMessageTimestamp(timestamp)).toBe(expectedTimeStr);
    });

    it('should format message from yesterday with date and time', () => {
      const now = new Date();
      // 24 hours ago - might still be today depending on time of day, so let's subtract 25 hours to be safe?
      // Or explicitly set the date to yesterday.
      const timestampDate = new Date(now);
      timestampDate.setDate(now.getDate() - 1);
      const timestamp = timestampDate.getTime() / 1000;

      const expectedTimeStr = timestampDate.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      const expectedDateStr = timestampDate.toLocaleDateString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
      });

      expect(formatMessageTimestamp(timestamp)).toBe(`${expectedDateStr} ${expectedTimeStr}`);
    });

    it('should format message from different year with date and time', () => {
      const now = new Date();
      // 1 year ago
      const timestampDate = new Date(now);
      timestampDate.setFullYear(now.getFullYear() - 1);
      const timestamp = timestampDate.getTime() / 1000;

      const expectedTimeStr = timestampDate.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      const expectedDateStr = timestampDate.toLocaleDateString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
      });

      expect(formatMessageTimestamp(timestamp)).toBe(`${expectedDateStr} ${expectedTimeStr}`);
    });

    it('should use current time if timestamp is not provided', () => {
      const now = new Date();
      // When no timestamp is provided, it uses "now"
      // Since we mocked "now", formatMessageTimestamp() will use that.

      const expectedTimeStr = now.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      expect(formatMessageTimestamp(undefined)).toBe(expectedTimeStr);
    });

    it('should handle midnight boundary correctly', () => {
      // Set "now" to 2024-01-15T12:00:00
      const now = new Date();

      // Message at 00:00:01 today
      const todayMidnight = new Date(now);
      todayMidnight.setHours(0, 0, 1, 0);

      const timestamp = todayMidnight.getTime() / 1000;

      const expectedTimeStr = todayMidnight.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      // Should be treated as today
      expect(formatMessageTimestamp(timestamp)).toBe(expectedTimeStr);
    });

    it('should handle yesterday 23:59:59 correctly', () => {
      // Set "now" to 2024-01-15T12:00:00
      const now = new Date();

      // Message at 23:59:59 yesterday
      const yesterdayEnd = new Date(now);
      yesterdayEnd.setDate(now.getDate() - 1);
      yesterdayEnd.setHours(23, 59, 59, 999);

      const timestamp = yesterdayEnd.getTime() / 1000;

      const expectedTimeStr = yesterdayEnd.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      const expectedDateStr = yesterdayEnd.toLocaleDateString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
      });

      // Should include date string
      expect(formatMessageTimestamp(timestamp)).toBe(`${expectedDateStr} ${expectedTimeStr}`);
    });
  });
});
