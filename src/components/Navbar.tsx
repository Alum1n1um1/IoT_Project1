'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { useState } from 'react'

export default function Navbar() {
  const pathname = usePathname()
  const router = useRouter()
  const [isRefreshing, setIsRefreshing] = useState(false)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      const response = await fetch('/api/refresh', {
        method: 'POST',
      })
      
      if (response.ok) {
        // Force page refresh to show new data
        router.refresh()
      }
    } catch (error) {
      console.error('Failed to refresh data:', error)
    } finally {
      setIsRefreshing(false)
    }
  }

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-dark-card border-b border-gray-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link href="/" className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-cyber-blue rounded flex items-center justify-center">
                <span className="text-dark-bg font-bold">IoT</span>
              </div>
              <span className="text-xl font-bold text-white">Security Analyzer</span>
            </Link>
          </div>
          
          <div className="flex items-center space-x-4">
            <Link 
              href="/" 
              className={`nav-link ${pathname === '/' ? 'nav-link-active' : ''}`}
            >
              Dashboard
            </Link>
            <Link 
              href="/threats" 
              className={`nav-link ${pathname === '/threats' ? 'nav-link-active' : ''}`}
            >
              Threat Analysis
            </Link>
            <button 
              className={`cyber-button ${isRefreshing ? 'opacity-50 cursor-not-allowed' : ''}`}
              onClick={handleRefresh}
              disabled={isRefreshing}
            >
              {isRefreshing ? 'Refreshing...' : 'Refresh Data'}
            </button>
          </div>
        </div>
      </div>
    </nav>
  )
}
