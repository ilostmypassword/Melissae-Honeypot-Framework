export default function DataTable({
  columns,
  data,
  emptyMessage = 'No data',
  renderCell,
  maxHeight = '280px',
}) {

  if (data.length === 0) {
    return (
      <div className="text-center py-12 text-text-muted italic border-2 border-dashed border-border rounded-xl">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto overflow-y-auto rounded-xl border border-border" style={{ maxHeight }}>
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="bg-surface-tertiary">
              {columns.map(col => (
                <th
                  key={col.key}
                  className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-text-secondary"
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {data.map((row, i) => (
              <tr
                key={i}
                className="hover:bg-surface-hover/50 transition-colors duration-100"
              >
                {columns.map(col => (
                  <td
                    key={col.key}
                    className={`px-4 py-3 text-text-primary ${col.className || ''}`}
                  >
                    {renderCell
                      ? renderCell(col.key, row[col.key], row)
                      : (row[col.key] ?? '-')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
