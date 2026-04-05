'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuthStore, roleColors, roleLabels } from '@/lib/auth';

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: { text: string; color: string };
}

const navItems: NavItem[] = [
  {
    label: 'Dashboard',
    href: '/dashboard',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
];

const moduleItems: NavItem[] = [
  {
    label: 'Vulnerability Management',
    href: '/vulnerability-management',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
  {
    label: 'Network Recon',
    href: '/network-recon',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="2" />
        <path d="M16.24 7.76a6 6 0 0 1 0 8.49M7.76 16.24a6 6 0 0 1 0-8.49M20.49 3.51a12 12 0 0 1 0 16.97M3.51 20.49a12 12 0 0 1 0-16.97" />
      </svg>
    ),
  },
  {
    label: 'Web App Testing',
    href: '/web-testing',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
  },
  {
    label: 'Breach Simulation',
    href: '/breach-simulation',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <circle cx="12" cy="12" r="6" />
        <circle cx="12" cy="12" r="2" />
      </svg>
    ),
  },
  {
    label: 'Risk Intelligence',
    href: '/risk-intelligence',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="18" y1="20" x2="18" y2="10" />
        <line x1="12" y1="20" x2="12" y2="4" />
        <line x1="6" y1="20" x2="6" y2="14" />
      </svg>
    ),
  },
  {
    label: 'TPRM',
    href: '/tprm',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
        <polyline points="9 22 9 12 15 12 15 22" />
      </svg>
    ),
  },
  {
    label: 'Auth Testing',
    href: '/auth-testing',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    badge: { text: 'RESTRICTED', color: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.15)] border-[rgba(255,59,59,0.4)]' },
  },
];

const toolItems: NavItem[] = [
  {
    label: 'Tool Panels',
    href: '/tools',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </svg>
    ),
  },
];

const settingsItems: NavItem[] = [
  {
    label: 'Settings',
    href: '/settings',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </svg>
    ),
  },
];

function NavLink({ item }: { item: NavItem }) {
  const pathname = usePathname();
  const isActive = pathname === item.href || pathname.startsWith(item.href + '/');

  return (
    <Link
      href={item.href}
      className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-150 relative group ${
        isActive
          ? 'bg-[#1a1f2e] text-[#00d4ff]'
          : 'text-[#8892a4] hover:bg-[#161b27] hover:text-[#e8eaf0]'
      }`}
    >
      {isActive && (
        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-[#00d4ff] rounded-r" />
      )}
      <span className={isActive ? 'text-[#00d4ff]' : 'text-[#8892a4] group-hover:text-[#e8eaf0]'}>
        {item.icon}
      </span>
      <span className="flex-1 truncate">{item.label}</span>
      {item.badge && (
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${item.badge.color}`}>
          {item.badge.text}
        </span>
      )}
    </Link>
  );
}

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuthStore();
  const router = useRouter();

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  return (
    <div className="flex h-screen bg-[#0a0b0d] overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 bg-[#0d0f14] border-r border-[#1e2028] flex flex-col shrink-0">
        {/* Logo */}
        <div className="px-4 py-5 border-b border-[#1e2028]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 shrink-0">
              <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M16 2L4 7v9c0 7.18 5.16 13.89 12 15.93C23.84 29.89 29 23.18 29 16V7L16 2z"
                  fill="rgba(0,212,255,0.15)"
                  stroke="#00d4ff"
                  strokeWidth="1.5"
                />
                <path
                  d="M10 16l4 4 8-8"
                  stroke="#00d4ff"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <div>
              <div className="text-[#e8eaf0] font-bold text-sm tracking-widest">LERUO</div>
              <div className="text-[#8892a4] text-[10px] tracking-wide">Security Platform</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          {/* Overview */}
          <div className="px-2 mb-2">
            <span className="text-[10px] font-bold text-[#3a3d4a] uppercase tracking-widest">Overview</span>
          </div>
          {navItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}

          {/* Modules */}
          <div className="px-2 pt-4 pb-2">
            <span className="text-[10px] font-bold text-[#3a3d4a] uppercase tracking-widest">Modules</span>
          </div>
          {moduleItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}

          {/* Tools */}
          <div className="px-2 pt-4 pb-2">
            <span className="text-[10px] font-bold text-[#3a3d4a] uppercase tracking-widest">Tools</span>
          </div>
          {toolItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}

          {/* Settings */}
          <div className="px-2 pt-4 pb-2">
            <span className="text-[10px] font-bold text-[#3a3d4a] uppercase tracking-widest">Settings</span>
          </div>
          {settingsItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </nav>

        {/* User section */}
        <div className="px-3 py-4 border-t border-[#1e2028]">
          {user ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-full bg-[#1e2028] flex items-center justify-center text-xs font-bold text-[#00d4ff] shrink-0">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-medium text-[#e8eaf0] truncate">{user.name}</div>
                  <div className="text-[10px] text-[#8892a4] truncate">{user.email}</div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${roleColors[user.role]}`}
                >
                  {roleLabels[user.role]}
                </span>
                <button
                  onClick={handleLogout}
                  className="text-[10px] text-[#8892a4] hover:text-[#ff3b3b] transition-colors"
                >
                  Logout
                </button>
              </div>
            </div>
          ) : (
            <div className="text-xs text-[#8892a4]">Not authenticated</div>
          )}
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
