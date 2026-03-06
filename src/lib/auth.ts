import { NextRequest } from 'next/server'
import { verifyToken, User } from '../services/authService'

export async function getAuthenticatedUser(request: NextRequest): Promise<User | null> {
  const token = request.cookies.get('auth-token')?.value
  
  if (!token) {
    return null
  }
  
  return await verifyToken(token)
}
