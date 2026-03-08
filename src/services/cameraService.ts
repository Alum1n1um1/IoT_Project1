import pool from '../lib/db'

export interface Camera {
  id: number
  name: string
  vendor: string
  product: string
  criticity: 'low' | 'medium' | 'high' | 'critical'
  created_at: string
  updated_at: string
}

export interface CreateCameraData {
  name: string
  vendor: string
  product: string
  criticity: 'low' | 'medium' | 'high' | 'critical'
}

export async function getUserCameras(userId: number): Promise<Camera[]> {
  try {
    const client = await pool.connect()
    
    const result = await client.query(
      'SELECT * FROM cameras WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    )
    
    client.release()
    return result.rows
  } catch (error) {
    console.error('Error fetching cameras:', error)
    return []
  }
}

export async function createCamera(userId: number, cameraData: CreateCameraData): Promise<Camera | null> {
  try {
    const client = await pool.connect()
    
    const result = await client.query(
      `INSERT INTO cameras (user_id, name, vendor, product, criticity) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING *`,
      [userId, cameraData.name, cameraData.vendor, cameraData.product, cameraData.criticity]
    )
    
    client.release()
    return result.rows[0]
  } catch (error) {
    console.error('Error creating camera:', error)
    return null
  }
}

export async function updateCamera(userId: number, cameraId: number, cameraData: Partial<CreateCameraData>): Promise<Camera | null> {
  try {
    const client = await pool.connect()
    
    const setParts = []
    const values = []
    let paramCounter = 1
    
    if (cameraData.name) {
      setParts.push(`name = $${paramCounter}`)
      values.push(cameraData.name)
      paramCounter++
    }
    if (cameraData.vendor) {
      setParts.push(`vendor = $${paramCounter}`)
      values.push(cameraData.vendor)
      paramCounter++
    }
    if (cameraData.product) {
      setParts.push(`product = $${paramCounter}`)
      values.push(cameraData.product)
      paramCounter++
    }
    if (cameraData.criticity) {
      setParts.push(`criticity = $${paramCounter}`)
      values.push(cameraData.criticity)
      paramCounter++
    }
    
    setParts.push(`updated_at = CURRENT_TIMESTAMP`)
    
    values.push(userId, cameraId)
    
    const result = await client.query(
      `UPDATE cameras SET ${setParts.join(', ')} 
       WHERE user_id = $${paramCounter} AND id = $${paramCounter + 1} 
       RETURNING *`,
      values
    )
    
    client.release()
    return result.rows[0] || null
  } catch (error) {
    console.error('Error updating camera:', error)
    return null
  }
}

export async function deleteCamera(userId: number, cameraId: number): Promise<boolean> {
  try {
    const client = await pool.connect()

    const result = await client.query(
      'DELETE FROM cameras WHERE user_id = $1 AND id = $2',
      [userId, cameraId]
    )

    client.release()
    return result.rowCount !== null && result.rowCount > 0
  } catch (error) {
    console.error('Error deleting camera:', error)
    return false
  }
}

export async function getCameraById(userId: number, cameraId: number): Promise<Camera | null> {
  try {
    const client = await pool.connect()

    const result = await client.query(
      'SELECT * FROM cameras WHERE id = $1 AND user_id = $2',
      [cameraId, userId]
    )

    client.release()
    return result.rows[0] || null
  } catch (error) {
    console.error('Error fetching camera:', error)
    return null
  }
}
