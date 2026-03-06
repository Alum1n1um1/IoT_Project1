import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import pool from '../lib/db'

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

export interface User {
  id: number
  username: string
}

export interface AuthResult {
  success: boolean
  user?: User
  token?: string
  message?: string
}

export async function authenticateUser(username: string, password: string): Promise<AuthResult> {
  try {
    const client = await pool.connect()
    
    const result = await client.query(
      'SELECT id, username, password_hash FROM users WHERE username = $1',
      [username]
    )
    
    client.release()
    
    if (result.rows.length === 0) {
      return { success: false, message: 'Utilisateur non trouvé' }
    }
    
    const user = result.rows[0]
    const isValidPassword = await bcrypt.compare(password, user.password_hash)
    
    if (!isValidPassword) {
      return { success: false, message: 'Mot de passe incorrect' }
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    )
    
    return {
      success: true,
      user: { id: user.id, username: user.username },
      token
    }
  } catch (error) {
    console.error('Authentication error:', error)
    return { success: false, message: 'Erreur d\'authentification' }
  }
}

export async function verifyToken(token: string): Promise<User | null> {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any
    return { id: decoded.userId, username: decoded.username }
  } catch (error) {
    return null
  }
}
