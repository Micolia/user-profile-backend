import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import pkg from 'pg'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

dotenv.config()

console.log('Env variables loaded')
console.log('DB_PASSWORD:', process.env.DB_PASSWORD)

const app = express()
app.use(cors())
app.use(express.json())

const { Pool } = pkg
const pool = new Pool({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT,
})


const JWT_SECRET = process.env.JWT_SECRET

// Middleware - log delle richieste
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})

// Middleware - verifica token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization
  if (!authHeader) return res.status(401).json({ message: 'Token mancante' })

  const token = authHeader.split(' ')[1]
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.email = decoded.email
    next()
  } catch (error) {
    res.status(401).json({ message: 'Token inválido' })
  }
}

// POST - Registrazione
app.post('/usuarios', async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body
    if (!email || !password || !rol || !lenguage) {
      return res.status(400).json({ message: 'Todos los campos son obligatorios' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)',
      [email, hashedPassword, rol, lenguage]
    )
    res.status(201).json({ message: 'Usuario registrado correctamente' })
  } catch (error) {
    console.error("❌ Errore:", error)
    res.status(500).json({ message: 'Error al registrar el usuario' })
  }
})

// POST - Login e generazione token
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
    const user = rows[0]

    if (!user) return res.status(401).json({ message: 'Credenciales incorrectas' })

    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) return res.status(401).json({ message: 'Credenciales incorrectas' })

    const token = jwt.sign({ email }, JWT_SECRET)
    res.json({ token })
  } catch (error) {
    res.status(500).json({ message: 'Error al iniciar sesión' })
  }
})

// GET - Dati utente autenticato
app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT email, rol, lenguage FROM usuarios WHERE email = $1', [req.email])
    if (!rows.length) return res.status(404).json({ message: 'Usuario no encontrado' })
    res.json(rows)
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los datos del usuario' })
  }
})

app.listen(process.env.PORT, () => {
  console.log(`Servidor encendido en http://localhost:${process.env.PORT}`)
})
