const protocolStyles = {
  ssh:    'bg-protocol-ssh/15 text-protocol-ssh',
  ftp:    'bg-protocol-ftp/15 text-protocol-ftp',
  http:   'bg-protocol-http/15 text-protocol-http',
  modbus: 'bg-protocol-modbus/15 text-protocol-modbus',
  mqtt:   'bg-protocol-mqtt/15 text-protocol-mqtt',
  telnet: 'bg-protocol-telnet/15 text-protocol-telnet',
}

// Colored tag for a network protocol
export function ProtocolTag({ protocol }) {
  const key = protocol?.toLowerCase() || 'unknown'
  return (
    <span
      className={`inline-block px-2.5 py-1 rounded-md text-xs font-semibold uppercase tracking-wide ${
        protocolStyles[key] || 'bg-border text-text-secondary'
      }`}
    >
      {protocol?.toUpperCase() || 'N/A'}
    </span>
  )
}

const verdictStyles = {
  benign:     'bg-verdict-benign/15 text-verdict-benign',
  suspicious: 'bg-verdict-suspicious/15 text-verdict-suspicious',
  malicious:  'bg-verdict-malicious/15 text-verdict-malicious',
}

// Colored tag for a threat verdict
export function VerdictTag({ verdict }) {
  const key = verdict?.toLowerCase() || 'unknown'
  return (
    <span
      className={`inline-block px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wide ${
        verdictStyles[key] || 'bg-border text-text-secondary'
      }`}
    >
      {(verdict || 'unknown').toUpperCase()}
    </span>
  )
}

const severityStyles = {
  low:      'bg-protocol-mqtt/15 text-protocol-mqtt',
  medium:   'bg-verdict-suspicious/15 text-verdict-suspicious',
  high:     'bg-protocol-ftp/15 text-protocol-ftp',
  critical: 'bg-verdict-malicious/15 text-verdict-malicious',
}

// Colored tag for an alert severity
export function SeverityTag({ severity }) {
  const key = severity?.toLowerCase() || 'medium'
  return (
    <span
      className={`inline-block px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-widest ${
        severityStyles[key] || 'bg-border text-text-secondary'
      }`}
    >
      {(severity || 'unknown').toUpperCase()}
    </span>
  )
}

const alertStatusStyles = {
  new:          'bg-verdict-malicious/15 text-verdict-malicious',
  acknowledged: 'bg-verdict-suspicious/15 text-verdict-suspicious',
  resolved:     'bg-verdict-benign/15 text-verdict-benign',
}

// Colored tag for an alert lifecycle status
export function AlertStatusTag({ status }) {
  const key = status?.toLowerCase() || 'new'
  return (
    <span
      className={`inline-block px-2.5 py-1 rounded-md text-[10px] font-semibold uppercase tracking-widest ${
        alertStatusStyles[key] || 'bg-border text-text-secondary'
      }`}
    >
      {(status || 'new').toUpperCase()}
    </span>
  )
}

