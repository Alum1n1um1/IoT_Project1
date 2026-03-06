import { NextRequest, NextResponse } from 'next/server'
import { authenticateUser } from '../../../../services/authService'

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()

    if (!username || !password) {
      return NextResponse.json(
        { success: false, message: 'Nom d\'utilisateur et mot de passe requis' },
        { status: 400 }
      )
    }

    const result = await authenticateUser(username, password)

    if (result.success && result.token) {
      const response = NextResponse.json(
        { success: true, user: result.user },
        { status: 200 }
      )

      // Set HTTP-only cookie
      response.cookies.set('auth-token', result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 // 24 hours
      })

      return response
    } else {
      return NextResponse.json(
        { success: false, message: result.message },
        { status: 401 }
      )
    }
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}
