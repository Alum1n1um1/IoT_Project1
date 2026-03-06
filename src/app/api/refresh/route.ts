import { NextRequest, NextResponse } from 'next/server'
import { refreshSecurityData } from '../../../services/securityService'

export async function POST(request: NextRequest) {
  try {
    const result = await refreshSecurityData()
    
    return NextResponse.json(result, { status: 200 })
  } catch (error) {
    return NextResponse.json(
      { success: false, message: 'Failed to refresh security data' },
      { status: 500 }
    )
  }
}
