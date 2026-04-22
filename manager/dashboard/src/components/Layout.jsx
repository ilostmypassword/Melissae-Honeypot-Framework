import { NavLink, useLocation } from 'react-router-dom'

const navSections = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Dashboard', icon: DashboardIcon },
      { to: '/agents', label: 'Agents', icon: AgentIcon },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { to: '/search', label: 'Search', icon: SearchIcon },
      { to: '/map', label: 'Map', icon: MapIcon },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/threats', label: 'Threat Intel', icon: ThreatIcon },
    ],
  },
]

// Main application layout with sidebar navigation
export default function Layout({ children }) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <nav className="w-[230px] bg-surface-secondary border-r border-border flex flex-col fixed top-0 left-0 h-screen z-50">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5">
          <img src="/logo.png" alt="Melissae" className="h-7 w-auto" />
          <div>
            <span className="text-base font-semibold text-text-primary tracking-tight block">
              Melissae
            </span>
            <span className="text-[9px] uppercase tracking-[0.2em] text-text-muted font-medium">
              Honeypot Framework
            </span>
          </div>
        </div>

        <div className="glow-line mx-4" />

        {/* Nav sections */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          {navSections.map(section => (
            <div key={section.label}>
              <p className="section-title px-3 mb-2">
                {section.label}
              </p>
              <div className="flex flex-col gap-0.5">
                {section.items.map(item => {
                  const isActive = item.to === '/'
                    ? location.pathname === '/'
                    : location.pathname.startsWith(item.to)
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 group relative ${
                        isActive
                          ? 'bg-accent/10 text-accent-hover'
                          : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover/50'
                      }`}
                    >
                      {isActive && (
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full bg-accent" />
                      )}
                      <item.icon active={isActive} />
                      {item.label}
                    </NavLink>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-border">
          <p className="text-[9px] text-text-muted uppercase tracking-[0.2em]">
            v2.1
          </p>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 ml-[230px] px-6 py-6 max-w-[1440px]">
        {children}
      </main>
    </div>
  )
}

function DashboardIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  )
}

function AgentIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <rect x="2" y="6" width="20" height="12" rx="2" />
      <line x1="6" y1="10" x2="6" y2="14" />
      <line x1="10" y1="10" x2="10" y2="14" />
      <line x1="14" y1="10" x2="14" y2="14" />
      <line x1="18" y1="10" x2="18" y2="14" />
    </svg>
  )
}

function SearchIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <circle cx="11" cy="11" r="7" />
      <line x1="16.5" y1="16.5" x2="21" y2="21" />
    </svg>
  )
}

function MapIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  )
}

function ThreatIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <path d="M12 2L2 7l10 5 10-5-10-5z" />
      <path d="M2 17l10 5 10-5" />
      <path d="M2 12l10 5 10-5" />
    </svg>
  )
}

