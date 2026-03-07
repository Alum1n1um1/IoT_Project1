import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '../../../../services/authService'
import { getCameraById } from '../../../../services/cameraService'
import { vulnerabilityService } from '../../../../services/vulnerabilityService'
import { cookies } from 'next/headers'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ cameraId: string }> }
) {
  try {
    // Resolve params promise (Next.js 16+)
    const resolvedParams = await params
    const cameraId = parseInt(resolvedParams.cameraId)
    if (isNaN(cameraId)) {
      return NextResponse.json({ error: 'Invalid camera ID' }, { status: 400 })
    }

    // Verify authentication
    const cookieStore = await cookies()
    const token = cookieStore.get('auth-token')?.value

    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const user = await verifyToken(token)
    if (!user) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 })
    }

    // Get camera from database using cameraService
    const camera = await getCameraById(user.id, cameraId)
    if (!camera) {
      return NextResponse.json({ error: 'Camera not found' }, { status: 404 })
    }

    // Enrich camera with vulnerability data
    const enrichedDevice = await vulnerabilityService.enrichDeviceWithVulns(camera)

    return NextResponse.json({
      success: true,
      device: {
        id: enrichedDevice.id,
        name: enrichedDevice.name,
        brand: camera.brand,
        model: camera.model,
        criticality: camera.criticity,
        manufacturer: enrichedDevice.manufacturer
      },
      vulnerabilities: enrichedDevice.vulnerabilities || {
        cves: [],
        cwes: [],
        kves: [],
        cvssScore: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lastUpdated: new Date().toISOString()
      }
    })
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error)
    return NextResponse.json(
      { error: 'Failed to fetch vulnerabilities', details: (error as Error).message },
      { status: 500 }
    )
  }
}
