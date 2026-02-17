import { NavLink } from 'react-router-dom'

const navItems = [
  { to: '/', label: 'Dashboard', icon: '⊞' },
  { to: '/map', label: 'Map', icon: '◎' },
  { to: '/threats', label: 'Threats', icon: '⚑' },
  { to: '/search', label: 'Search', icon: '⌕' },
]

export default function Layout({ children }) {
  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <nav className="w-56 bg-surface-secondary border-r border-border flex flex-col fixed top-0 left-0 h-screen z-50">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-border">
          <img src="/logo.png" alt="Melissae" className="h-7 w-auto" />
          <span className="text-base font-semibold text-text-primary tracking-tight">
            Melissae
          </span>
        </div>

        {/* Nav links */}
        <div className="flex-1 flex flex-col gap-0.5 px-3 py-4">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                  isActive
                    ? 'bg-accent/15 text-accent-hover'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
                }`
              }
            >
              <span className="text-base w-5 text-center opacity-70">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-border">
          <p className="text-[10px] text-text-muted uppercase tracking-widest">Melissae Honeypot Framework</p>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 ml-56 px-6 py-6 max-w-[1440px]">
        {children}
      </main>
    </div>
  )
}
