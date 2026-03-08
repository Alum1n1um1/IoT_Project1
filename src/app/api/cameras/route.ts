import { NextRequest, NextResponse } from 'next/server'
import { getAuthenticatedUser } from '../../../lib/auth'
import { getUserCameras, createCamera } from '../../../services/cameraService'

export async function GET(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request)
    
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Non autorisé' },
        { status: 401 }
      )
    }
    
    const cameras = await getUserCameras(user.id)
    
    return NextResponse.json({ success: true, cameras })
  } catch (error) {
    console.error('Error fetching cameras:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request)
    
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Non autorisé' },
        { status: 401 }
      )
    }
    
    const { name, vendor, product, criticity } = await request.json()
    
    if (!name || !vendor || !product || !criticity) {
      return NextResponse.json(
        { success: false, message: 'Tous les champs sont requis' },
        { status: 400 }
      )
    }
    
    const camera = await createCamera(user.id, { name, vendor, product, criticity })
    
    if (camera) {
      return NextResponse.json({ success: true, camera })
    } else {
      return NextResponse.json(
        { success: false, message: 'Erreur lors de la création' },
        { status: 500 }
      )
    }
  } catch (error) {
    console.error('Error creating camera:', error)
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    )
  }
}
