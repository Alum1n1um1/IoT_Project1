import { NextRequest, NextResponse } from 'next/server'
import { getAuthenticatedUser } from '../../../../lib/auth'

export async function GET(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request)
    
    if (user) {
      return NextResponse.json({ success: true, user })
    } else {
      return NextResponse.json(
        { success: false, message: 'Non authentifié' },
        { status: 401 }
      )
    }
  } catch (error) {
    console.error('Auth check error:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}
