import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatMessageTimestamp } from './timeUtils';

describe('formatMessageTimestamp', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should format timestamp from today correctly (time only)', () => {
    // Set current time to a specific date: 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Timestamp for 1 hour ago (same day)
    const timestamp = Math.floor(now.getTime() / 1000) - 3600;
    const date = new Date(timestamp * 1000);

    const expected = date.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(formatMessageTimestamp(timestamp)).toBe(expected);
  });

  it('should format timestamp from yesterday correctly (date + time)', () => {
    // Set current time to a specific date: 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Timestamp for 25 hours ago (yesterday)
    const timestamp = Math.floor(now.getTime() / 1000) - 25 * 3600;
    const date = new Date(timestamp * 1000);

    const expectedDate = date.toLocaleDateString('en-US', {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
    });
    const expectedTime = date.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(formatMessageTimestamp(timestamp)).toBe(`${expectedDate} ${expectedTime}`);
  });

  it('should format timestamp from different year correctly (date + time)', () => {
    // Set current time to a specific date: 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    // Timestamp for 1 year ago
    const timestamp = Math.floor(now.getTime() / 1000) - 365 * 24 * 3600;
    const date = new Date(timestamp * 1000);

    const expectedDate = date.toLocaleDateString('en-US', {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
    });
    const expectedTime = date.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(formatMessageTimestamp(timestamp)).toBe(`${expectedDate} ${expectedTime}`);
  });

  it('should default to current time when no timestamp is provided', () => {
    // Set current time to a specific date: 2024-01-15 12:00:00
    const now = new Date('2024-01-15T12:00:00');
    vi.setSystemTime(now);

    const expected = now.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(formatMessageTimestamp()).toBe(expected);
  });

  it('should handle exact midnight correctly', () => {
    // Set current time to a specific date: 2024-01-15 00:00:00
    const now = new Date('2024-01-15T00:00:00');
    vi.setSystemTime(now);

    const timestamp = Math.floor(now.getTime() / 1000);
    const date = new Date(timestamp * 1000);

    const expected = date.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    expect(formatMessageTimestamp(timestamp)).toBe(expected);
  });

  it('should handle single digit hours/minutes correctly', () => {
    // Set current time to a specific date: 2024-01-15 09:05:00
    const now = new Date('2024-01-15T09:05:00');
    vi.setSystemTime(now);

    const timestamp = Math.floor(now.getTime() / 1000);
    const date = new Date(timestamp * 1000);

    const expected = date.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    // Check specifically that it includes expected format like "9:05 AM"
    // Note: The specific output depends on implementation of toLocaleTimeString in the environment
    // but we check consistency with toLocaleTimeString called on date object.
    expect(formatMessageTimestamp(timestamp)).toBe(expected);
  });
});
