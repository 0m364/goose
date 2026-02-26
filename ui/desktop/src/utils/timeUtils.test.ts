import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatMessageTimestamp } from './timeUtils';

describe('formatMessageTimestamp', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should format timestamp from today correctly (just time)', () => {
    // Set system time to a specific date/time: 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Create a timestamp for 10:00:00 (2 hours earlier) on the same day
    const timestampDate = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const timestamp = timestampDate.getTime() / 1000;

    const result = formatMessageTimestamp(timestamp);

    // Should only contain the time string since it's the same day
    const expectedTime = timestampDate.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(result).toBe(expectedTime);
  });

  it('should format timestamp from yesterday correctly (date + time)', () => {
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Create a timestamp for 25 hours earlier (should be yesterday)
    const timestampDate = new Date(now.getTime() - 25 * 60 * 60 * 1000);
    const timestamp = timestampDate.getTime() / 1000;

    const result = formatMessageTimestamp(timestamp);

    const expectedTime = timestampDate.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });
    const expectedDate = timestampDate.toLocaleDateString('en-US', {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
    });

    expect(result).toBe(`${expectedDate} ${expectedTime}`);
  });

  it('should format timestamp from a different year correctly (date + time)', () => {
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Create a timestamp for 1 year earlier
    const timestampDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
    const timestamp = timestampDate.getTime() / 1000;

    const result = formatMessageTimestamp(timestamp);

    const expectedTime = timestampDate.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });
    const expectedDate = timestampDate.toLocaleDateString('en-US', {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
    });

    expect(result).toBe(`${expectedDate} ${expectedTime}`);
  });

  it('should use current time if timestamp is not provided', () => {
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    const result = formatMessageTimestamp();

    // Should use "now" (which is today)
    const expectedTime = now.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(result).toBe(expectedTime);
  });

  it('should handle midnight correctly (same day)', () => {
    // Set system time to 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Set timestamp to midnight of the same day (00:00:00)
    // Note: This relies on local timezone. We assume the test runner's local time is consistent.
    // To be safe, we construct the midnight relative to the "now" date object in local time.
    const midnight = new Date(now);
    midnight.setHours(0, 0, 0, 0);
    const timestamp = midnight.getTime() / 1000;

    const result = formatMessageTimestamp(timestamp);

    const expectedTime = midnight.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(result).toBe(expectedTime);
  });
});
