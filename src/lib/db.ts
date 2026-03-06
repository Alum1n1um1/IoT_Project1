import { Pool } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@postgres:5432/iot_security',
  ssl: false // Disable SSL for development
})

export default pool
