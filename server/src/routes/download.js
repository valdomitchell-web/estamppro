import express from 'express'
import path from 'path'
import fs from 'fs'

/**
 * We store temp downloads on a global Map set by your apply route.
 * globalThis.__downloads : Map<id, relativePath>
 * (Set in your apply route when saving to disk.)
 */
const router = express.Router()

router.get('/:id', (req, res) => {
  const id = req.params.id
  const map = globalThis.__downloads || new Map()
  const rel = map.get(id)
  if (!rel) return res.status(404).json({ error: 'Not found' })

  const abs = path.join(process.cwd(), rel)
  if (!fs.existsSync(abs)) return res.status(404).json({ error: 'Missing file' })
  res.download(abs)
})

export default router

