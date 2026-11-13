import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface SOCNotification {
  id: string
  title: string
  message: string
  severity: 'critical' | 'high' | 'medium' | 'info'
  timestamp: string
  read: boolean
  link?: string
  source?: string
}

interface NotificationState {
  notifications: SOCNotification[]
  unreadCount: () => number
  markAsRead: (id: string) => void
  markAllAsRead: () => void
  removeNotification: (id: string) => void
  clearAll: () => void
  addNotification: (n: Omit<SOCNotification, 'id' | 'timestamp' | 'read'>) => void
}

const INITIAL_NOTIFICATIONS: SOCNotification[] = [
  {
    id: 'notif-1',
    title: 'Critical Phishing Email Intercepted',
    message: 'High risk spoofed PayPal notification with credential harvesting link detected.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    read: false,
    link: '/investigation-history',
    source: 'Email Shield',
  },
  {
    id: 'notif-2',
    title: 'Disguised Executable Blocked',
    message: 'Attachment invoice.pdf detected as Windows PE binary via magic bytes analysis.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    read: false,
    link: '/investigation-history',
    source: 'Attachment Sandbox',
  },
  {
    id: 'notif-3',
    title: 'Authentication-Results Spoof Attempt',
    message: 'External attacker attempted header injection with forged passing SPF/DKIM.',
    severity: 'high',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    read: false,
    link: '/investigation-history',
    source: 'Header Analyzer',
  },
  {
    id: 'notif-4',
    title: 'Automated Mail-Flow Ingestion Active',
    message: 'Inbound MTA webhook connector is listening and operational.',
    severity: 'info',
    timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    read: true,
    link: '/settings',
    source: 'Mail-Flow Engine',
  },
]

export const useNotificationStore = create<NotificationState>()(
  persist(
    (set, get) => ({
      notifications: INITIAL_NOTIFICATIONS,

      unreadCount: () => get().notifications.filter((n) => !n.read).length,

      markAsRead: (id: string) =>
        set((state) => ({
          notifications: state.notifications.map((n) =>
            n.id === id ? { ...n, read: true } : n
          ),
        })),

      markAllAsRead: () =>
        set((state) => ({
          notifications: state.notifications.map((n) => ({ ...n, read: true })),
        })),

      removeNotification: (id: string) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),

      clearAll: () => set({ notifications: [] }),

      addNotification: (n) =>
        set((state) => ({
          notifications: [
            {
              ...n,
              id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
              timestamp: new Date().toISOString(),
              read: false,
            },
            ...state.notifications,
          ],
        })),
    }),
    {
      name: 'phishguard_notifications',
    }
  )
)
