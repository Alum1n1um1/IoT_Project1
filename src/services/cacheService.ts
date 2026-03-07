// Simple in-memory cache service with TTL
import { VulnerabilityCacheEntry } from '../types/nvd'

interface CacheEntry {
  data: VulnerabilityCacheEntry
  expiresAt: number
}

class CacheService {
  private cache = new Map<string, CacheEntry>()

  /**
   * Get cached vulnerability data if not expired
   * @param deviceKey Format: "brand:model" (lowercase)
   * @returns Cached data or null if not found/expired
   */
  async get(deviceKey: string): Promise<VulnerabilityCacheEntry | null> {
    const entry = this.cache.get(deviceKey)

    if (!entry) {
      return null
    }

    // Check if expired
    if (entry.expiresAt < Date.now()) {
      this.cache.delete(deviceKey)
      return null
    }

    return entry.data
  }

  /**
   * Store vulnerability data in cache with TTL
   * @param deviceKey Format: "brand:model" (lowercase)
   * @param data Vulnerability cache entry with TTL defined
   */
  async set(deviceKey: string, data: VulnerabilityCacheEntry): Promise<void> {
    const expiresAt = Date.now() + data.ttl * 1000

    this.cache.set(deviceKey, {
      data,
      expiresAt
    })
  }

  /**
   * Invalidate cache entry
   */
  async invalidate(deviceKey: string): Promise<void> {
    this.cache.delete(deviceKey)
  }

  /**
   * Clear all cache
   */
  async clear(): Promise<void> {
    this.cache.clear()
  }

  /**
   * Get cache statistics (for debugging)
   */
  getStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    }
  }
}

// Singleton instance
export const cacheService = new CacheService()
