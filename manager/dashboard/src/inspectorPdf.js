import { jsPDF } from 'jspdf'

// ----- Layout constants (points, A4) --------------------------------------- //
const MARGIN = 42
const HEADER_H = 76
const BODY_FS = 10
const LINE = 14

// ----- Palette ------------------------------------------------------------- //
const COL = {
  brand: [15, 23, 42],      // slate-900 header band
  accent: [37, 99, 235],    // blue-600 headings / rules
  text: [38, 43, 56],       // body text
  muted: [120, 128, 140],   // meta / footer
  faint: [226, 230, 236],   // hairlines
  zebra: [246, 248, 251],   // table odd rows
  thBg: [37, 99, 235],      // table header background
  white: [255, 255, 255],
}

// ----- Inline tokenizer ---------------------------------------------------- //
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
function wordsFromSegments(segments) {
  const words = []
  for (const seg of segments) {
    const parts = seg.text.split(/(\s+)/)
    for (const p of parts) {
      if (p === '') continue
      words.push({ ...seg, text: p, space: /^\s+$/.test(p) })
    }
  }
  return words
}

function fontFor(doc, w) {
  if (w.code) doc.setFont('courier', w.bold ? 'bold' : 'normal')
  else if (w.bold && w.italic) doc.setFont('helvetica', 'bolditalic')
  else if (w.bold) doc.setFont('helvetica', 'bold')
  else if (w.italic) doc.setFont('helvetica', 'italic')
  else doc.setFont('helvetica', 'normal')
}

// ----- Document builder ---------------------------------------------------- //
export function exportReportToPdf(markdown, meta = {}) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4', compress: true })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const usableW = pageW - MARGIN * 2
  const bottom = pageH - MARGIN - 6

  let y = 0

  const setFill = c => doc.setFillColor(c[0], c[1], c[2])
  const setText = c => doc.setTextColor(c[0], c[1], c[2])
  const setDraw = c => doc.setDrawColor(c[0], c[1], c[2])

  const newPage = () => {
    doc.addPage()
    y = MARGIN + 8
  }

  const ensure = h => {
    if (y + h > bottom) newPage()
  }

  // Branded header band (page 1 only)
  const drawHeader = () => {
    setFill(COL.brand)
    doc.rect(0, 0, pageW, HEADER_H, 'F')
    setFill(COL.accent)
    doc.roundedRect(MARGIN, 22, 30, 30, 6, 6, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(17)
    setText(COL.white)
    doc.text('I', MARGIN + 15, 43, { align: 'center' })
    doc.setFontSize(17)
    doc.text('Inspector — Threat Briefing', MARGIN + 44, 38)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(9)
    setText([170, 178, 190])
    doc.text('Melissae Honeypot Framework · AI Threat Analyst', MARGIN + 44, 54)
    y = HEADER_H + 26
  }

  // Meta line under the header
  const drawMeta = () => {
    const bits = []
    if (meta.generated_at) bits.push(`Generated  ${new Date(meta.generated_at).toLocaleString()}`)
    if (meta.threats_analyzed != null) bits.push(`Threats  ${meta.threats_analyzed}`)
    if (meta.model) bits.push(`Model  ${meta.model}`)
    if (!bits.length) return
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8.5)
    setText(COL.muted)
    doc.text(bits.join('      '), MARGIN, y)
    y += 10
    setDraw(COL.faint)
    doc.setLineWidth(0.6)
    doc.line(MARGIN, y, pageW - MARGIN, y)
    y += 20
  }

  // Lay out rich (inline-styled) text with word wrapping. Returns new y.
  const drawRich = (text, x, maxW, opts = {}) => {
    const fs = opts.fs ?? BODY_FS
    const lh = opts.lh ?? LINE
    const color = opts.color ?? COL.text
    const words = wordsFromSegments(tokenizeInline(text))
    doc.setFontSize(fs)
    let cx = x
    let lineWords = []
    const flush = () => {
      let lx = x
      for (const w of lineWords) {
        fontFor(doc, w)
        setText(w.code ? COL.accent : color)
        doc.text(w.text, lx, y)
        lx += doc.getTextWidth(w.text)
      }
      lineWords = []
    }
    for (const w of words) {
      fontFor(doc, w)
      const ww = doc.getTextWidth(w.text)
      if (cx + ww > x + maxW && lineWords.length && !w.space) {
        ensure(lh)
        flush()
        y += lh
        cx = x
      }
      if (w.space && cx === x) continue // drop leading spaces
      lineWords.push(w)
      cx += ww
    }
    if (lineWords.length) {
      ensure(lh)
      flush()
      y += lh
    }
    return y
  }

  // ----- Table rendering --------------------------------------------------- //
  const colWidthsFor = header => {
    const cols = header.length
    return new Array(cols).fill(usableW / cols)
  }

  const rowHeight = (cells, colW, fs) => {
    const padY = 5
    let maxLines = 1
    cells.forEach((c, ci) => {
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(fs)
      const wrapped = doc.splitTextToSize(stripBasic(c || ''), colW[ci] - 12)
      maxLines = Math.max(maxLines, wrapped.length)
    })
    return maxLines * (fs + 2) + padY * 2
  }

  const renderTable = (header, rows) => {
    const cols = header.length
    const colW = colWidthsFor(header)
    const padX = 6
    const padY = 5

    const drawRow = (cells, kind, idx) => {
      const fs = kind === 'head' ? 8.6 : 8.8
      const h = rowHeight(cells, colW, fs)
      ensure(h)
      const top = y
      if (kind === 'head') { setFill(COL.thBg); doc.rect(MARGIN, top, usableW, h, 'F') }
      else if (idx % 2 === 1) { setFill(COL.zebra); doc.rect(MARGIN, top, usableW, h, 'F') }

      let x = MARGIN
      cells.forEach((c, ci) => {
        doc.setFont('helvetica', kind === 'head' ? 'bold' : 'normal')
        doc.setFontSize(fs)
        setText(kind === 'head' ? COL.white : COL.text)
        const wrapped = doc.splitTextToSize(stripBasic(c || ''), colW[ci] - padX * 2)
        doc.text(wrapped, x + padX, top + padY + fs)
        x += colW[ci]
      })

      setDraw(kind === 'head' ? COL.thBg : COL.faint)
      doc.setLineWidth(0.5)
      for (let ci = 1; ci < cols && kind !== 'head'; ci++) {
        doc.line(MARGIN + colW.slice(0, ci).reduce((a, b) => a + b, 0), top,
                 MARGIN + colW.slice(0, ci).reduce((a, b) => a + b, 0), top + h)
      }
      setDraw(COL.faint)
      doc.line(MARGIN, top + h, pageW - MARGIN, top + h)
      y += h
    }

    const startY = y
    drawRow(header, 'head', 0)
    rows.forEach((r, ri) => drawRow(r, 'body', ri))

    // Outer border around the whole table (handles single-page tables)
    if (y > startY) {
      setDraw(COL.faint)
      doc.setLineWidth(0.6)
      doc.rect(MARGIN, startY, usableW, y - startY)
    }
  }

  // ----- List item --------------------------------------------------------- //
  const renderListItem = (marker, text) => {
    const indent = 16
    ensure(LINE)
    doc.setFont('helvetica', marker === '•' ? 'bold' : 'normal')
    doc.setFontSize(BODY_FS)
    setText(COL.accent)
    doc.text(marker, MARGIN + 2, y)
    drawRich(text, MARGIN + indent, usableW - indent)
  }

  // ----- Render the markdown body ------------------------------------------ //
  drawHeader()
  drawMeta()

  const lines = String(markdown || '').replace(/\r/g, '').split('\n')
  let i = 0
  let orderedIdx = 0

  while (i < lines.length) {
    const line = lines[i].trim()

    if (!line) { y += LINE * 0.5; orderedIdx = 0; i++; continue }

    if (line.startsWith('### ')) {
      ensure(LINE * 2)
      y += 6
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(10.5)
      setText(COL.accent)
      doc.text(stripBasic(line.slice(4)).toUpperCase(), MARGIN, y)
      y += LINE + 2
      orderedIdx = 0; i++; continue
    }
    if (line.startsWith('## ')) {
      ensure(LINE * 2.4)
      y += 10
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(14)
      setText(COL.brand)
      doc.text(stripBasic(line.slice(3)), MARGIN, y)
      y += 8
      setDraw(COL.accent)
      doc.setLineWidth(1.4)
      doc.line(MARGIN, y, MARGIN + 38, y)
      y += LINE
      orderedIdx = 0; i++; continue
    }
    if (line.startsWith('# ')) {
      ensure(LINE * 2.4)
      y += 8
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(16)
      setText(COL.brand)
      doc.text(stripBasic(line.slice(2)), MARGIN, y)
      y += LINE * 1.5
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
      y += 8
      orderedIdx = 0
      continue
    }

    // Numbered list
    const om = line.match(/^(\d+)\.\s+(.*)$/)
    if (om) {
      orderedIdx += 1
      renderListItem(`${orderedIdx}.`, om[2])
      i++; continue
    }

    // Bullet list
    if (line.startsWith('- ') || line.startsWith('* ')) {
      renderListItem('•', line.slice(2))
      orderedIdx = 0; i++; continue
    }

    // Paragraph
    drawRich(line, MARGIN, usableW)
    orderedIdx = 0; i++
  }

  // ----- Footers on every page --------------------------------------------- //
  const pages = doc.getNumberOfPages()
  const stampStr = new Date().toLocaleDateString()
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    setDraw(COL.faint)
    doc.setLineWidth(0.5)
    doc.line(MARGIN, pageH - MARGIN + 4, pageW - MARGIN, pageH - MARGIN + 4)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    setText(COL.muted)
    doc.text('Melissae · Inspector', MARGIN, pageH - MARGIN + 16)
    doc.text(`Page ${p} of ${pages}`, pageW / 2, pageH - MARGIN + 16, { align: 'center' })
    doc.text(stampStr, pageW - MARGIN, pageH - MARGIN + 16, { align: 'right' })
  }

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
  doc.save(`inspector-briefing-${stamp}.pdf`)
}

// Strip markdown emphasis markers for plain-text contexts (headings, tables).
function stripBasic(text) {
  return String(text)
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
