import { useState, useEffect } from 'react'
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
    label: 'Statistics',
    items: [
      { to: '/stats/activity', label: 'Traffic', icon: ActivityIcon },
      { to: '/stats/attackers', label: 'Threats', icon: AttackerIcon },
    ],
  },
  {
    label: 'Explore',
    items: [
      { to: '/search', label: 'Search', icon: SearchIcon },
      { to: '/map', label: 'Geo Map', icon: MapIcon },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/threats', label: 'Threat Intelligence', icon: ThreatIcon },
    ],
  },
]

// Main application layout with sidebar navigation
export default function Layout({ children }) {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  // Close sidebar on route change (mobile nav)
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

  // Close sidebar on Escape key
  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') setSidebarOpen(false) }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  return (
    <div className="min-h-screen flex">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <nav className={`w-[230px] bg-surface-secondary border-r border-border flex flex-col fixed top-0 left-0 h-screen z-50 transition-transform duration-300 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}>
        {/* Logo */}
        <div className="flex items-center justify-between gap-3 px-5 py-5">
          <div className="flex items-center gap-3 min-w-0">
            <img src="/logo.png" alt="Melissae" className="h-7 w-auto shrink-0" />
            <div className="min-w-0">
              <span className="text-base font-semibold text-text-primary tracking-tight block truncate">
                Melissae
              </span>
              <span className="text-[9px] uppercase tracking-[0.2em] text-text-muted font-medium">
                Honeypot Framework
              </span>
            </div>
          </div>
          {/* Close button (mobile only) */}
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden shrink-0 p-1 rounded-md text-text-muted hover:text-text-primary hover:bg-surface-hover/50 transition-colors"
            aria-label="Close menu"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
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
            v2.2
          </p>
        </div>
      </nav>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-[230px]">
        {/* Mobile topbar */}
        <header className="lg:hidden flex items-center gap-3 px-4 py-3 bg-surface-secondary border-b border-border sticky top-0 z-30">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-hover/50 transition-colors"
            aria-label="Open menu"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
          </button>
          <img src="/logo.png" alt="Melissae" className="h-6 w-auto" />
          <span className="text-sm font-semibold text-text-primary tracking-tight">Melissae</span>
        </header>

        <main className="flex-1 px-4 py-4 sm:px-6 sm:py-6 min-w-0">
          {children}
        </main>
      </div>
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

function ActivityIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  )
}

function AttackerIcon({ active }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 transition-colors ${active ? 'text-accent' : 'text-text-muted group-hover:text-text-secondary'}`}>
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="4" />
      <line x1="12" y1="2" x2="12" y2="6" />
      <line x1="12" y1="18" x2="12" y2="22" />
      <line x1="2" y1="12" x2="6" y2="12" />
      <line x1="18" y1="12" x2="22" y2="12" />
    </svg>
  )
}

