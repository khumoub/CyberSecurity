import { create } from 'zustand';

export type UserRole = 'admin' | 'analyst' | 'junior_analyst' | 'tprm_manager' | 'read_only';

export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  org_id: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
  setUser: (user: User) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: typeof window !== 'undefined' ? localStorage.getItem('leruo_token') : null,
  isAuthenticated: typeof window !== 'undefined' ? !!localStorage.getItem('leruo_token') : false,

  login: (user: User, token: string) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('leruo_token', token);
    }
    set({ user, token, isAuthenticated: true });
  },

  logout: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('leruo_token');
    }
    set({ user: null, token: null, isAuthenticated: false });
  },

  setUser: (user: User) => set({ user }),
}));

export const roleColors: Record<UserRole, string> = {
  admin: 'text-[#ff3b3b] bg-[rgba(255,59,59,0.15)] border-[rgba(255,59,59,0.3)]',
  analyst: 'text-[#00d4ff] bg-[rgba(0,212,255,0.15)] border-[rgba(0,212,255,0.3)]',
  junior_analyst: 'text-[#4fc3f7] bg-[rgba(79,195,247,0.15)] border-[rgba(79,195,247,0.3)]',
  tprm_manager: 'text-[#ffcc00] bg-[rgba(255,204,0,0.15)] border-[rgba(255,204,0,0.3)]',
  read_only: 'text-[#8892a4] bg-[rgba(136,146,164,0.15)] border-[rgba(136,146,164,0.3)]',
};

export const roleLabels: Record<UserRole, string> = {
  admin: 'Admin',
  analyst: 'Analyst',
  junior_analyst: 'Junior Analyst',
  tprm_manager: 'TPRM Manager',
  read_only: 'Read Only',
};
