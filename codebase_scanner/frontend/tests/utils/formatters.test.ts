import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { formatPercentage, formatSeverity, formatRelativeTime } from '@/utils/formatters'

describe('formatters', () => {
  describe('formatPercentage', () => {
    it('formats number as percentage with default decimals', () => {
      expect(formatPercentage(75.5)).toBe('75.5%')
      expect(formatPercentage(100)).toBe('100.0%')
      expect(formatPercentage(0)).toBe('0.0%')
    })

    it('formats number as percentage with custom decimals', () => {
      expect(formatPercentage(75.567, 2)).toBe('75.57%')
      expect(formatPercentage(33.333, 0)).toBe('33%')
      expect(formatPercentage(99.999, 3)).toBe('99.999%')
    })
  })

  describe('formatSeverity', () => {
    it('capitalizes severity levels correctly', () => {
      expect(formatSeverity('critical')).toBe('Critical')
      expect(formatSeverity('high')).toBe('High')
      expect(formatSeverity('medium')).toBe('Medium')
      expect(formatSeverity('low')).toBe('Low')
      expect(formatSeverity('info')).toBe('Info')
    })

    it('handles already capitalized input', () => {
      expect(formatSeverity('CRITICAL')).toBe('Critical')
      expect(formatSeverity('HIGH')).toBe('High')
    })

    it('handles mixed case input', () => {
      expect(formatSeverity('cRiTiCaL')).toBe('Critical')
      expect(formatSeverity('MeDiUm')).toBe('Medium')
    })
  })

  describe('formatRelativeTime', () => {
    let mockDate: Date

    beforeEach(() => {
      mockDate = new Date('2024-01-01T12:00:00Z')
      vi.useFakeTimers()
      vi.setSystemTime(mockDate)
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('returns "Just now" for very recent times', () => {
      const recentDate = new Date(mockDate.getTime() - 30 * 1000) // 30 seconds ago
      expect(formatRelativeTime(recentDate)).toBe('Just now')
    })

    it('formats minutes correctly', () => {
      const oneMinuteAgo = new Date(mockDate.getTime() - 1 * 60 * 1000)
      expect(formatRelativeTime(oneMinuteAgo)).toBe('1 minute ago')

      const fiveMinutesAgo = new Date(mockDate.getTime() - 5 * 60 * 1000)
      expect(formatRelativeTime(fiveMinutesAgo)).toBe('5 minutes ago')
    })

    it('formats hours correctly', () => {
      const oneHourAgo = new Date(mockDate.getTime() - 1 * 60 * 60 * 1000)
      expect(formatRelativeTime(oneHourAgo)).toBe('1 hour ago')

      const threeHoursAgo = new Date(mockDate.getTime() - 3 * 60 * 60 * 1000)
      expect(formatRelativeTime(threeHoursAgo)).toBe('3 hours ago')
    })

    it('formats days correctly', () => {
      const oneDayAgo = new Date(mockDate.getTime() - 1 * 24 * 60 * 60 * 1000)
      expect(formatRelativeTime(oneDayAgo)).toBe('1 day ago')

      const threeDaysAgo = new Date(mockDate.getTime() - 3 * 24 * 60 * 60 * 1000)
      expect(formatRelativeTime(threeDaysAgo)).toBe('3 days ago')
    })
  })
})