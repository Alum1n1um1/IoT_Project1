import { NextRequest, NextResponse } from 'next/server'
import { getAuthenticatedUser } from '../../../../lib/auth'
import { updateCamera, deleteCamera } from '../../../../services/cameraService'

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedUser(request)
    
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Non autorisé' },
        { status: 401 }
      )
    }
    
    const { id } = await params
    const cameraId = parseInt(id)
    const updateData = await request.json()
    
    const camera = await updateCamera(user.id, cameraId, updateData)
    
    if (camera) {
      return NextResponse.json({ success: true, camera })
    } else {
      return NextResponse.json(
        { success: false, message: 'Caméra non trouvée' },
        { status: 404 }
      )
    }
  } catch (error) {
    console.error('Error updating camera:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedUser(request)
    
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Non autorisé' },
        { status: 401 }
      )
    }
    
    const { id } = await params
    const cameraId = parseInt(id)
    const success = await deleteCamera(user.id, cameraId)
    
    if (success) {
      return NextResponse.json({ success: true })
    } else {
      return NextResponse.json(
        { success: false, message: 'Caméra non trouvée' },
        { status: 404 }
      )
    }
  } catch (error) {
    console.error('Error deleting camera:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}
