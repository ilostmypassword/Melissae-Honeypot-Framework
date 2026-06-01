import { jsPDF } from 'jspdf'

// Lightweight Markdown -> PDF renderer for Inspector briefings.

const MARGIN = 48
const LINE = 16

function stripInline(text) {
  return String(text)
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/\*(.*?)\*/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .trim()
}

function parseTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map(c => stripInline(c))
}

// Export an Inspector report (markdown) as a downloadable PDF file.
export function exportReportToPdf(markdown, meta = {}) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const usableW = pageW - MARGIN * 2
  let y = MARGIN

  const ensureSpace = h => {
    if (y + h > pageH - MARGIN) {
      doc.addPage()
      y = MARGIN
    }
  }

  // Title block
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(20)
  doc.setTextColor(20, 20, 20)
  doc.text('Inspector — Threat Briefing', MARGIN, y)
  y += 24

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(120, 120, 120)
  const metaBits = []
  if (meta.generated_at) metaBits.push(`Generated: ${new Date(meta.generated_at).toLocaleString()}`)
  if (meta.threats_analyzed != null) metaBits.push(`Threats analyzed: ${meta.threats_analyzed}`)
  if (meta.model) metaBits.push(`Model: ${meta.model}`)
  if (metaBits.length) {
    doc.text(metaBits.join('    '), MARGIN, y)
    y += 18
  }
  doc.setDrawColor(220, 220, 220)
  doc.line(MARGIN, y, pageW - MARGIN, y)
  y += 18

  const lines = String(markdown || '').replace(/\r/g, '').split('\n')
  let i = 0
  while (i < lines.length) {
    const raw = lines[i]
    const line = raw.trim()

    // Blank line
    if (!line) { y += LINE * 0.5; i++; continue }

    // Headings
    if (line.startsWith('### ')) {
      ensureSpace(LINE * 1.6)
      y += LINE * 0.4
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(11)
      doc.setTextColor(180, 90, 30)
      doc.text(stripInline(line.slice(4)).toUpperCase(), MARGIN, y)
      y += LINE
      i++
      continue
    }
    if (line.startsWith('## ')) {
      ensureSpace(LINE * 1.8)
      y += LINE * 0.5
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(14)
      doc.setTextColor(30, 30, 30)
      doc.text(stripInline(line.slice(3)), MARGIN, y)
      y += LINE * 1.2
      i++
      continue
    }
    if (line.startsWith('# ')) {
      ensureSpace(LINE * 2)
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(16)
      doc.setTextColor(20, 20, 20)
      doc.text(stripInline(line.slice(2)), MARGIN, y)
      y += LINE * 1.4
      i++
      continue
    }

    // Tables: a header row followed by a separator row of dashes
    if (line.startsWith('|') && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      const header = parseTableRow(line)
      const rows = []
      i += 2
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(parseTableRow(lines[i]))
        i++
      }
      const cols = header.length
      const colW = usableW / cols
      const drawRow = (cells, bold) => {
        doc.setFont('helvetica', bold ? 'bold' : 'normal')
        doc.setFontSize(9)
        doc.setTextColor(bold ? 40 : 70, bold ? 40 : 70, bold ? 40 : 70)
        // Determine row height from wrapped cells
        const wrapped = cells.map(c => doc.splitTextToSize(c || '', colW - 10))
        const rowH = Math.max(LINE, ...wrapped.map(w => w.length * LINE * 0.8)) + 6
        ensureSpace(rowH)
        if (bold) {
          doc.setFillColor(240, 240, 240)
          doc.rect(MARGIN, y - LINE * 0.8, usableW, rowH, 'F')
        }
        wrapped.forEach((w, c) => {
          doc.text(w, MARGIN + c * colW + 4, y)
        })
        y += rowH
        doc.setDrawColor(225, 225, 225)
        doc.line(MARGIN, y - LINE * 0.6, pageW - MARGIN, y - LINE * 0.6)
      }
      drawRow(header, true)
      rows.forEach(r => drawRow(r, false))
      y += LINE * 0.4
      continue
    }

    // Bullet list
    if (line.startsWith('- ') || line.startsWith('* ')) {
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(10)
      doc.setTextColor(55, 55, 55)
      const text = stripInline(line.slice(2))
      const wrapped = doc.splitTextToSize(text, usableW - 16)
      ensureSpace(wrapped.length * LINE)
      doc.text('•', MARGIN, y)
      doc.text(wrapped, MARGIN + 14, y)
      y += wrapped.length * LINE
      i++
      continue
    }

    // Paragraph
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(10)
    doc.setTextColor(55, 55, 55)
    const wrapped = doc.splitTextToSize(stripInline(line), usableW)
    ensureSpace(wrapped.length * LINE)
    doc.text(wrapped, MARGIN, y)
    y += wrapped.length * LINE
    i++
  }

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
  doc.save(`inspector-briefing-${stamp}.pdf`)
}
