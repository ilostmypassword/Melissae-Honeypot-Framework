import { jsPDF } from 'jspdf'

// Layout constants in points (A4)
const MARGIN = 48
const HEADER_H = 86
const RUNNING_H = 34   // slim header on pages 2+
const BODY_FS = 10
const LINE = 14.5
const CODE_PAD = 2   // horizontal padding inside inline code chips

// Palette mirrors tailwind.config.js dashboard tokens
const COL = {
  surface: [10, 14, 19],     // #0a0e13  dark header band
  tertiary: [24, 32, 42],    // #18202a  table header / ink
  ink: [33, 41, 54],         // body headings
  text: [46, 53, 66],        // body text (readable on white)
  accent: [127, 142, 163],   // #7f8ea3  muted slate accent
  accentDeep: [95, 110, 132],// darker accent for code / rules on white
  muted: [114, 125, 139],    // #727d8b  meta / footer
  faint: [223, 228, 234],    // hairlines
  zebra: [246, 247, 250],    // table odd rows / panels
  codeBg: [237, 240, 244],   // inline code background
  headText: [216, 222, 231], // #d8dee7  light text on dark band
  white: [255, 255, 255],
  benign: [122, 168, 137],   // #7aa889
  suspicious: [196, 163, 106],// #c4a36a
  malicious: [192, 125, 125], // #c07d7d
}

// Blend a colour towards white (a = 1 keeps it, a = 0 is white).
const tint = (c, a) => c.map(v => Math.round(255 - (255 - v) * a))
// Darken a colour for text drawn on its own tint.
const shade = (c, a) => c.map(v => Math.round(v * a))

const VERDICTS = ['malicious', 'suspicious', 'benign']

const verdictColor = word => {
  const w = String(word || '').toLowerCase()
  return VERDICTS.includes(w) ? COL[w] : null
}

const postureColor = text => {
  if (/critical/i.test(text)) return COL.malicious
  if (/elevated/i.test(text)) return COL.suspicious
  if (/calm/i.test(text)) return COL.benign
  return COL.accent
}

const scoreColor = value => {
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  if (n >= 70) return COL.malicious
  if (n >= 40) return COL.suspicious
  return COL.benign
}

// Logo loading (async, cached)
let _logoCache // { dataURL, w, h } | null
async function loadLogo() {
  if (_logoCache !== undefined) return _logoCache
  try {
    const res = await fetch('/logo.png')
    if (!res.ok) throw new Error('logo missing')
    const blob = await res.blob()
    const dataURL = await new Promise((resolve, reject) => {
      const fr = new FileReader()
      fr.onload = () => resolve(fr.result)
      fr.onerror = reject
      fr.readAsDataURL(blob)
    })
    const dims = await new Promise(resolve => {
      const img = new Image()
      img.onload = () => resolve({ w: img.naturalWidth, h: img.naturalHeight })
      img.onerror = () => resolve({ w: 1, h: 1 })
      img.src = dataURL
    })
    _logoCache = { dataURL, w: dims.w, h: dims.h }
  } catch {
    _logoCache = null
  }
  return _logoCache
}

// Inline tokenizer
// Split a markdown string into styled segments: {text, bold, italic, code}.
function tokenizeInline(text) {
  const segments = []
  const re = /(\*\*([^*]+)\*\*|__([^_]+)__|`([^`]+)`|\*([^*]+)\*|\[([^\]]+)\]\([^)]*\))/g
  let last = 0
  let m
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) {
      segments.push({ text: text.slice(last, m.index), bold: false, italic: false, code: false })
    }
    if (m[2] != null) segments.push({ text: m[2], bold: true, italic: false, code: false })
    else if (m[3] != null) segments.push({ text: m[3], bold: true, italic: false, code: false })
    else if (m[4] != null) segments.push({ text: m[4], bold: false, italic: false, code: true })
    else if (m[5] != null) segments.push({ text: m[5], bold: false, italic: true, code: false })
    else if (m[6] != null) segments.push({ text: m[6], bold: false, italic: false, code: false })
    last = re.lastIndex
  }
  if (last < text.length) {
    segments.push({ text: text.slice(last), bold: false, italic: false, code: false })
  }
  return segments.length ? segments : [{ text, bold: false, italic: false, code: false }]
}

// Expand styled segments into per-word tokens (whitespace kept as tokens).
// Inline code stays a single unbreakable token so it renders as one chip.
function wordsFromSegments(segments, base = {}) {
  const words = []
  for (const seg of segments) {
    if (seg.code) {
      words.push({ ...seg, space: false })
      continue
    }
    const parts = seg.text.split(/(\s+)/)
    for (const p of parts) {
      if (p === '') continue
      words.push({
        ...seg,
        bold: seg.bold || !!base.bold,
        italic: seg.italic || !!base.italic,
        text: p,
        space: /^\s+$/.test(p),
      })
    }
  }
  return words
}

// One consistent typeface family (Helvetica) throughout — no Courier mixing.
function fontFor(doc, w) {
  if (w.bold && w.italic) doc.setFont('helvetica', 'bolditalic')
  else if (w.bold) doc.setFont('helvetica', 'bold')
  else if (w.italic) doc.setFont('helvetica', 'italic')
  else doc.setFont('helvetica', 'normal')
}

// Text sanitization
const PDF_SAFE_HIGH = new Set([
  0x2013, 0x2014,                 // – —
  0x2018, 0x2019, 0x201c, 0x201d, // ‘ ’ “ ”
  0x2022,                         // •
  0x2026,                         // …
])

function sanitizeText(input) {
  let s = String(input ?? '')
    .replace(/[→➔➜➤⇒➙➙]/g, ' to ')
    .replace(/[←⇐]/g, ' from ')
    .replace(/[✓✔✅]/g, '[ok]')
    .replace(/[✗✘❌]/g, '[x]')
    .replace(/⚠/g, '!')
    .replace(/ /g, ' ')
    .replace(/[​-‍︎️]/g, '')
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0)
    if (cp === 0x09 || cp === 0x0a || cp === 0x0d) { out += ch; continue }
    if (cp >= 0x20 && cp <= 0x7e) { out += ch; continue }   // ASCII
    if (cp >= 0xa0 && cp <= 0xff) { out += ch; continue }   // Latin-1 supplement
    if (PDF_SAFE_HIGH.has(cp)) { out += ch; continue }      // safe typography
    // anything else (emoji, flags, symbols) is dropped
  }
  return out
}

// Document builder
export async function exportReportToPdf(markdown, meta = {}) {
  const logo = await loadLogo()
  const doc = new jsPDF({ unit: 'pt', format: 'a4', compress: true })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const usableW = pageW - MARGIN * 2
  const bottom = pageH - MARGIN - 10
  const generated = meta.generated_at ? new Date(meta.generated_at) : new Date()

  doc.setProperties({
    title: 'Inspektor Threat Briefing',
    subject: `Threat briefing generated ${generated.toISOString()}`,
    creator: 'Melissae Honeypot Framework',
  })

  let y = 0

  const setFill = c => doc.setFillColor(c[0], c[1], c[2])
  const setText = c => doc.setTextColor(c[0], c[1], c[2])
  const setDraw = c => doc.setDrawColor(c[0], c[1], c[2])

  // jsPDF's getTextWidth() applies kerning but text() draws unkerned glyphs,
  // so measure without kerning or words run into the following space.
  const textWidth = t => doc.getStringUnitWidth(t, { kerning: {} }) * doc.getFontSize() / doc.internal.scaleFactor

  const newPage = () => {
    doc.addPage()
    y = MARGIN + RUNNING_H
  }

  const ensure = h => {
    if (y + h > bottom) newPage()
  }

  // Branded header band (page 1 only)
  const drawHeader = () => {
    setFill(COL.surface)
    doc.rect(0, 0, pageW, HEADER_H, 'F')
    // thin accent rule along the bottom of the band
    setFill(COL.accent)
    doc.rect(0, HEADER_H - 2, pageW, 2, 'F')

    let textX = MARGIN
    if (logo) {
      const boxH = 38
      const w = Math.max(1, (logo.w / logo.h) * boxH)
      doc.addImage(logo.dataURL, 'PNG', MARGIN, (HEADER_H - boxH) / 2 - 1, w, boxH)
      textX = MARGIN + w + 14
    }

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(7.5)
    setText(COL.accent)
    doc.text('INSPEKTOR  ·  AI THREAT ANALYST', textX, 36, { charSpace: 1 })
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(21)
    setText(COL.white)
    doc.text('Threat Briefing', textX, 59)

    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8.5)
    setText(COL.headText)
    doc.text('Melissae Honeypot Framework', pageW - MARGIN, 36, { align: 'right' })
    doc.text(generated.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }),
      pageW - MARGIN, 50, { align: 'right' })
    y = HEADER_H + 20
  }

  // Meta panel under the header: label / value columns
  const drawMeta = () => {
    const items = []
    items.push(['GENERATED', generated.toLocaleString()])
    if (meta.threats_analyzed != null) items.push(['THREATS ANALYZED', String(meta.threats_analyzed)])
    if (meta.model) items.push(['MODEL', sanitizeText(meta.model)])
    const h = 40
    setFill(COL.zebra)
    doc.roundedRect(MARGIN, y, usableW, h, 4, 4, 'F')
    const colW = usableW / items.length
    items.forEach(([label, value], i) => {
      const x = MARGIN + 14 + i * colW
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(6.8)
      setText(COL.muted)
      doc.text(label, x, y + 15, { charSpace: 0.7 })
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(9.5)
      setText(COL.ink)
      doc.text(doc.splitTextToSize(value, colW - 20)[0], x, y + 29)
      if (i > 0) {
        setDraw(COL.faint)
        doc.setLineWidth(0.6)
        doc.line(MARGIN + i * colW, y + 9, MARGIN + i * colW, y + h - 9)
      }
    })
    y += h + 20
  }

  // Rich (inline-styled) text
  const wordWidth = w => {
    fontFor(doc, w)
    return textWidth(w.text) + (w.code ? CODE_PAD * 2 : 0)
  }

  // Break text into lines of measured words without drawing anything.
  const layoutRich = (text, maxW, opts = {}) => {
    doc.setFontSize(opts.fs ?? BODY_FS)
    const words = wordsFromSegments(tokenizeInline(sanitizeText(text)), opts)
    const lines = []
    let cur = []
    let cx = 0
    for (const w of words) {
      const ww = wordWidth(w)
      if (cx + ww > maxW && cur.length && !w.space) {
        while (cur.length && cur[cur.length - 1].space) cur.pop()
        lines.push(cur)
        cur = []
        cx = 0
      }
      if (w.space && cx === 0) continue // drop leading spaces
      cur.push({ ...w, width: ww })
      cx += ww
    }
    if (cur.length) lines.push(cur)
    return lines
  }

  const drawWord = (w, x, fs, color) => {
    fontFor(doc, w)
    if (w.code) {
      const vc = verdictColor(w.text)
      setFill(vc ? tint(vc, 0.22) : COL.codeBg)
      doc.roundedRect(x, y - fs + 1.5, w.width, fs + 3, 2, 2, 'F')
      setText(vc ? shade(vc, 0.62) : COL.accentDeep)
      doc.text(w.text, x + CODE_PAD, y)
    } else {
      setText(color)
      doc.text(w.text, x, y)
    }
  }

  const drawLines = (lines, x, opts = {}) => {
    const fs = opts.fs ?? BODY_FS
    const lh = opts.lh ?? LINE
    const color = opts.color ?? COL.text
    doc.setFontSize(fs)
    for (const line of lines) {
      ensure(lh)
      let lx = x
      for (const w of line) {
        drawWord(w, lx, fs, color)
        lx += w.width
      }
      y += lh
    }
    return y
  }

  const drawRich = (text, x, maxW, opts = {}) => drawLines(layoutRich(text, maxW, opts), x, opts)

  // Posture callout
  const renderPosture = text => {
    const color = postureColor(text)
    const padX = 14
    const padTop = 12
    const labelH = 14
    const lines = layoutRich(text, usableW - padX * 2 - 4)
    const h = padTop + labelH + lines.length * LINE + 6
    ensure(h + 8)
    const top = y
    setFill(tint(color, 0.12))
    doc.roundedRect(MARGIN, top, usableW, h, 4, 4, 'F')
    setFill(color)
    doc.rect(MARGIN, top, 3.5, h, 'F')

    doc.setFont('helvetica', 'bold')
    doc.setFontSize(7)
    setText(shade(color, 0.7))
    doc.text('OVERALL POSTURE', MARGIN + padX + 4, top + padTop + 4, { charSpace: 0.8 })

    y = top + padTop + labelH + 9
    drawLines(lines, MARGIN + padX + 4, { color: COL.ink })
    y = top + h + 14
  }

  // Section headings
  const renderSection = title => {
    // keep the heading with at least a few lines of its content
    ensure(LINE * 5)
    y += 10
    const label = stripBasic(title).toUpperCase()
    setFill(COL.accent)
    doc.rect(MARGIN, y - 9, 3, 12, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(9.5)
    setText(COL.ink)
    const cs = 0.9
    doc.text(label, MARGIN + 10, y, { charSpace: cs })
    const tw = textWidth(label) + cs * label.length
    setDraw(COL.faint)
    doc.setLineWidth(0.6)
    doc.line(MARGIN + 10 + tw + 10, y - 3.5, pageW - MARGIN, y - 3.5)
    y += LINE + 3
  }

  // Table rendering
  const CELL_PAD_X = 7
  const CELL_PAD_Y = 5

  const columnKinds = header => header.map(h => {
    const t = stripBasic(h).toLowerCase()
    if (/score/.test(t)) return 'score'
    if (/verdict/.test(t)) return 'verdict'
    if (/^ip\b|address/.test(t)) return 'ip'
    return 'text'
  })

  const cellFont = (kind, colKind) => {
    if (kind === 'head') doc.setFont('helvetica', 'bold')
    else if (colKind === 'ip') doc.setFont('helvetica', 'bold')
    else doc.setFont('helvetica', 'normal')
  }

  // Size columns from their content: short columns keep their natural width,
  // long free-text columns share whatever room is left.
  const colWidthsFor = (header, rows, kinds) => {
    const cols = header.length
    const natural = new Array(cols).fill(0)
    const minW = new Array(cols).fill(40)
    const measure = (cells, kind) => cells.forEach((c, ci) => {
      if (ci >= cols) return
      cellFont(kind, kinds[ci])
      doc.setFontSize(kind === 'head' ? 7.6 : 8.8)
      const txt = kind === 'head' ? stripBasic(c || '').toUpperCase() : stripBasic(c || '')
      const extra = kind === 'head' ? txt.length * 0.6 : (kinds[ci] === 'score' ? 10 : 0)
      natural[ci] = Math.max(natural[ci], textWidth(txt) + extra + CELL_PAD_X * 2)
      const longest = txt.split(/\s+/).reduce((m, wd) => Math.max(m, textWidth(wd)), 0)
      minW[ci] = Math.max(minW[ci], longest + extra + CELL_PAD_X * 2)
    })
    measure(header, 'head')
    rows.forEach(r => measure(r, 'body'))

    const total = natural.reduce((a, b) => a + b, 0)
    if (total <= usableW) {
      // spare room goes to the widest (free-text) column
      const widest = natural.indexOf(Math.max(...natural))
      natural[widest] += usableW - total
      return natural
    }
    const share = usableW / cols
    const fixed = natural.map(n => n <= share)
    const fixedW = natural.reduce((a, n, ci) => a + (fixed[ci] ? n : 0), 0)
    const flexNatural = natural.reduce((a, n, ci) => a + (fixed[ci] ? 0 : n), 0)
    const room = usableW - fixedW
    return natural.map((n, ci) => (fixed[ci] ? n : Math.max(minW[ci], (n / flexNatural) * room)))
  }

  const renderTable = (header, rows) => {
    const cols = header.length
    const kinds = columnKinds(header)
    const colW = colWidthsFor(header, rows, kinds)
    // normalise ragged rows to the header width
    rows = rows.map(r => Array.from({ length: cols }, (_, ci) => r[ci] ?? ''))

    const wrapCell = (c, ci, kind) => {
      cellFont(kind, kinds[ci])
      const fs = kind === 'head' ? 7.6 : 8.8
      doc.setFontSize(fs)
      const txt = kind === 'head' ? stripBasic(c || '').toUpperCase() : stripBasic(c || '')
      return doc.splitTextToSize(txt, colW[ci] - CELL_PAD_X * 2)
    }

    const rowHeight = (cells, kind) => {
      const fs = kind === 'head' ? 7.6 : 8.8
      const maxLines = cells.reduce((m, c, ci) => Math.max(m, wrapCell(c, ci, kind).length), 1)
      return maxLines * (fs + 3) + CELL_PAD_Y * 2 - 1
    }

    const drawPill = (text, color, x, top, fs) => {
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(fs)
      const tw = textWidth(text)
      setFill(tint(color, 0.22))
      doc.roundedRect(x, top + CELL_PAD_Y - 1.5, tw + 10, fs + 4, 2.5, 2.5, 'F')
      setText(shade(color, 0.62))
      doc.text(text, x + 5, top + CELL_PAD_Y + fs - 0.5)
    }

    const drawRow = (cells, kind, idx) => {
      const fs = kind === 'head' ? 7.6 : 8.8
      const h = rowHeight(cells, kind)
      if (y + h > bottom) {
        newPage()
        if (kind !== 'head') drawRow(header, 'head', 0) // repeat header on new page
      }
      const top = y
      if (kind === 'head') {
        setFill(COL.tertiary)
        doc.roundedRect(MARGIN, top, usableW, h, 3, 3, 'F')
      } else if (idx % 2 === 1) {
        setFill(COL.zebra)
        doc.rect(MARGIN, top, usableW, h, 'F')
      }

      let x = MARGIN
      cells.forEach((c, ci) => {
        const plain = stripBasic(c || '')
        const ck = kinds[ci]
        if (kind === 'body' && ck === 'score' && scoreColor(plain)) {
          drawPill(plain, scoreColor(plain), x + CELL_PAD_X - 2, top, fs)
        } else if (kind === 'body' && ck === 'verdict' && verdictColor(plain)) {
          drawPill(plain, verdictColor(plain), x + CELL_PAD_X - 2, top, fs)
        } else {
          const wrapped = wrapCell(c, ci, kind)
          const isUntracked = kind === 'body' && /^untracked$/i.test(plain)
          if (isUntracked) doc.setFont('helvetica', 'italic')
          if (kind === 'head') setText(COL.headText)
          else if (isUntracked) setText(COL.muted)
          else if (ck === 'ip') setText(COL.ink)
          else setText(COL.text)
          doc.text(wrapped, x + CELL_PAD_X, top + CELL_PAD_Y + fs,
            kind === 'head' ? { charSpace: 0.6, lineHeightFactor: (fs + 3) / fs } : { lineHeightFactor: (fs + 3) / fs })
        }
        x += colW[ci]
      })

      if (kind !== 'head') {
        setDraw(COL.faint)
        doc.setLineWidth(0.5)
        doc.line(MARGIN, top + h, pageW - MARGIN, top + h)
      }
      y += h
    }

    drawRow(header, 'head', 0)
    rows.forEach((r, ri) => drawRow(r, 'body', ri))
  }

  // List item
  const renderListItem = (marker, text) => {
    const indent = 18
    const lines = layoutRich(text, usableW - indent)
    // keep short items whole; long ones may still split
    ensure(LINE * Math.min(lines.length, 3))
    if (marker === 'bullet') {
      setFill(COL.accent)
      doc.circle(MARGIN + 5, y - 3.4, 1.9, 'F')
    } else {
      setFill(COL.tertiary)
      doc.circle(MARGIN + 5.5, y - 3.4, 6.2, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(7.2)
      setText(COL.white)
      doc.text(marker, MARGIN + 5.5, y - 0.9, { align: 'center' })
    }
    drawLines(lines, MARGIN + indent)
    y += 3
  }

  // Render the markdown body
  drawHeader()
  drawMeta()

  const lines = String(markdown || '').replace(/\r/g, '').split('\n')
  let i = 0
  let orderedIdx = 0
  let seenSection = false

  while (i < lines.length) {
    const line = lines[i].trim()

    if (!line) { y += LINE * 0.4; orderedIdx = 0; i++; continue }

    // Horizontal rule
    if (/^([-*_])\1{2,}$/.test(line)) {
      ensure(LINE)
      setDraw(COL.faint)
      doc.setLineWidth(0.6)
      doc.line(MARGIN, y - 4, pageW - MARGIN, y - 4)
      y += LINE * 0.6
      orderedIdx = 0; i++; continue
    }

    if (line.startsWith('### ')) {
      renderSection(line.slice(4))
      seenSection = true
      orderedIdx = 0; i++; continue
    }
    if (line.startsWith('## ') || line.startsWith('# ')) {
      const title = stripBasic(line.replace(/^#+\s+/, ''))
      // the branded header already carries the report title
      if (!/^threat briefing$/i.test(title)) {
        ensure(LINE * 4)
        y += 10
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(line.startsWith('# ') ? 16 : 14)
        setText(COL.ink)
        doc.text(title, MARGIN, y)
        y += LINE * 1.3
      }
      orderedIdx = 0; i++; continue
    }

    // Posture line -> coloured callout
    const pm = line.match(/^\*\*Posture:?\*\*:?\s*(.*)$/i)
    if (pm) {
      renderPosture(pm[1])
      orderedIdx = 0; i++; continue
    }

    // Tables
    if (line.startsWith('|') && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      const header = parseRow(line)
      const rows = []
      i += 2
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(parseRow(lines[i]))
        i++
      }
      renderTable(header, rows)
      y += 10
      orderedIdx = 0
      continue
    }

    // Numbered list
    const om = line.match(/^(\d+)\.\s+(.*)$/)
    if (om) {
      orderedIdx += 1
      renderListItem(String(orderedIdx), om[2])
      i++; continue
    }

    // Bullet list
    if (line.startsWith('- ') || line.startsWith('* ')) {
      renderListItem('bullet', line.slice(2))
      orderedIdx = 0; i++; continue
    }

    // Paragraph (the lead-in before the first section reads as an intro)
    if (!seenSection) drawRich(line, MARGIN, usableW, { italic: true, color: COL.muted, fs: 10.5, lh: 16 })
    else drawRich(line, MARGIN, usableW)
    y += 2
    orderedIdx = 0; i++
  }

  // Running header + footer on every page
  const pages = doc.getNumberOfPages()
  const stampStr = generated.toLocaleString()
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    if (p > 1) {
      setFill(COL.accent)
      doc.rect(0, 0, pageW, 3, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(7.5)
      setText(COL.muted)
      doc.text('INSPEKTOR THREAT BRIEFING', MARGIN, MARGIN - 8, { charSpace: 0.8 })
      doc.setFont('helvetica', 'normal')
      doc.text(stampStr, pageW - MARGIN, MARGIN - 8, { align: 'right' })
    }
    setDraw(COL.faint)
    doc.setLineWidth(0.5)
    doc.line(MARGIN, pageH - MARGIN + 6, pageW - MARGIN, pageH - MARGIN + 6)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7.5)
    setText(COL.muted)
    doc.text('Melissae · Inspektor', MARGIN, pageH - MARGIN + 18)
    doc.text(`${p} / ${pages}`, pageW / 2, pageH - MARGIN + 18, { align: 'center' })
    doc.text(`Generated ${stampStr}`, pageW - MARGIN, pageH - MARGIN + 18, { align: 'right' })
  }

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
  doc.save(`inspektor-briefing-${stamp}.pdf`)
}

// Strip markdown emphasis markers for plain-text contexts (headings, tables).
function stripBasic(text) {
  return sanitizeText(text)
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/__(.*?)__/g, '$1')
    .replace(/\*(.*?)\*/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .trim()
}

function parseRow(line) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map(c => c.trim())
}
