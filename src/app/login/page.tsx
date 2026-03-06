'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        router.push('/')
        router.refresh()
      } else {
        setError(data.message || 'Erreur de connexion')
      }
    } catch (error) {
      setError('Erreur de connexion')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-bg">
      <div className="max-w-md w-full space-y-8 p-8">
        <div>
          <div className="flex justify-center">
            <div className="w-12 h-12 bg-cyber-blue rounded flex items-center justify-center">
              <span className="text-dark-bg font-bold text-lg">IoT</span>
            </div>
          </div>
          <h2 className="mt-6 text-center text-3xl font-bold text-white">
            Connexion
          </h2>
          <p className="mt-2 text-center text-sm text-gray-400">
            Analyseur de Sécurité IoT
          </p>
        </div>
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-cyber-red bg-opacity-20 border border-cyber-red text-cyber-red px-4 py-2 rounded">
              {error}
            </div>
          )}
          
          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-300">
                Nom d'utilisateur
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-dark-card border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-blue focus:border-transparent"
                placeholder="jules"
              />
            </div>
            
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                Mot de passe
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-dark-card border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-blue focus:border-transparent"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className={`w-full cyber-button ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isLoading ? 'Connexion...' : 'Se connecter'}
          </button>
        </form>
      </div>
    </div>
  )
}
