'use client'

import React, { useState, useEffect } from 'react'
import {
  Settings,
  Lock,
  Unlock,
  User,
  Shield,
  CheckCircle,
  XCircle,
  Copy,
  Zap,
  Bell,
  Mail,
  Server,
  Cpu,
  Key,
  MessageSquare,
  Send,
  Clock,
  ShieldCheck,
  AlertTriangle,
  UserCheck,
  Sparkles,
  Layers,
  ChevronRight,
  Filter,
  Check,
  X,
  ExternalLink,
  Users,
  UserPlus,
  ShieldAlert,
  Trash2,
  RefreshCw,
} from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { useAuthStore } from '@/store/authStore'
import { apiClient } from '@/lib/api'
import { cn } from '@/lib/utils'

interface FeatureItem {
  key: string
  name: string
  description: string
  category: string
  requires_approval: boolean
  status: 'unlocked' | 'approved' | 'pending' | 'locked'
  can_access: boolean
}

interface FeatureRequestItem {
  id: string
  user_id?: string
  user_email?: string
  user_name?: string
  feature_key: string
  feature_name: string
  justification: string
  status: 'pending' | 'approved' | 'rejected'
  admin_notes?: string
  created_at: string
  reviewed_at?: string
}

interface AdminMessageItem {
  id: string
  user_id?: string
  user_email?: string
  user_name?: string
  subject: string
  message: string
  status: 'unread' | 'read' | 'replied'
  admin_reply?: string
  created_at: string
  replied_at?: string
}

interface ManagedUser {
  id: string
  email: string
  username: string
  display_name?: string
  role: string
  is_active: boolean
  last_login_at?: string
  created_at?: string
}

export default function SettingsPage() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'super_admin' || user?.role === 'security_admin'

  // Tab State
  const [activeTab, setActiveTab] = useState<'profile' | 'features' | 'contact' | 'approvals'>(
    'profile'
  )

  // Super Admin Sub-tabs
  const [adminSubTab, setAdminSubTab] = useState<'users' | 'approvals' | 'messages' | 'policies'>(
    'users'
  )

  // Policy States (Admin only)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [isChanging, setIsChanging] = useState(false)
  const [autoQuarantine, setAutoQuarantine] = useState(true)
  const [quarantineThreshold, setQuarantineThreshold] = useState(75)
  const [quarantineAction, setQuarantineAction] = useState('quarantine')

  // Feature Catalog & Requests State
  const [features, setFeatures] = useState<FeatureItem[]>([])
  const [myRequests, setMyRequests] = useState<FeatureRequestItem[]>([])
  const [adminRequests, setAdminRequests] = useState<FeatureRequestItem[]>([])
  const [selectedFeatureToRequest, setSelectedFeatureToRequest] = useState<FeatureItem | null>(null)
  const [requestJustification, setRequestJustification] = useState('')
  const [isSubmittingRequest, setIsSubmittingRequest] = useState(false)

  // Contact Admin Messages State
  const [myMessages, setMyMessages] = useState<AdminMessageItem[]>([])
  const [adminMessages, setAdminMessages] = useState<AdminMessageItem[]>([])
  const [contactSubject, setContactSubject] = useState('')
  const [contactMessage, setContactMessage] = useState('')
  const [isSendingMessage, setIsSendingMessage] = useState(false)

  // Admin Reply State
  const [replyingToMessage, setReplyingToMessage] = useState<AdminMessageItem | null>(null)
  const [adminReplyText, setAdminReplyText] = useState('')
  const [isSubmittingReply, setIsSubmittingReply] = useState(false)

  // Admin Review Notes State
  const [reviewingRequest, setReviewingRequest] = useState<FeatureRequestItem | null>(null)
  const [adminNotes, setAdminNotes] = useState('')
  const [isProcessingApproval, setIsProcessingApproval] = useState(false)

  // Super Admin: User Management State
  const [managedUsers, setManagedUsers] = useState<ManagedUser[]>([])
  const [isLoadingUsers, setIsLoadingUsers] = useState(false)
  const [showAddUserModal, setShowAddUserModal] = useState(false)
  const [newUserEmail, setNewUserEmail] = useState('')
  const [newUserName, setNewUserName] = useState('')
  const [newUserDisplayName, setNewUserDisplayName] = useState('')
  const [newUserPassword, setNewUserPassword] = useState('')
  const [newUserRole, setNewUserRole] = useState('analyst')
  const [isCreatingUser, setIsCreatingUser] = useState(false)

  // Load Data
  const loadData = async () => {
    try {
      // 1. Feature catalog
      const catRes = await apiClient.get('/feature-approvals/catalog')
      if (catRes.data?.data?.features) {
        setFeatures(catRes.data.data.features)
      }

      // 2. User's own requests
      const myReqRes = await apiClient.get('/feature-approvals/requests/my')
      if (myReqRes.data?.data) {
        setMyRequests(myReqRes.data.data)
      }

      // 3. User's messages
      const myMsgRes = await apiClient.get('/feature-approvals/contact/my')
      if (myMsgRes.data?.data) {
        setMyMessages(myMsgRes.data.data)
      }

      // 4. Admin endpoints if admin
      if (isAdmin) {
        const allReqRes = await apiClient.get('/feature-approvals/admin/requests')
        if (allReqRes.data?.data) {
          setAdminRequests(allReqRes.data.data)
        }

        const allMsgRes = await apiClient.get('/feature-approvals/admin/messages')
        if (allMsgRes.data?.data) {
          setAdminMessages(allMsgRes.data.data)
        }

        // Fetch managed users
        fetchManagedUsers()
      }
    } catch {
      // Background fetch failure
    }
  }

  const fetchManagedUsers = async () => {
    setIsLoadingUsers(true)
    try {
      const res = await apiClient.get('/users?page=1&page_size=100')
      if (res.data?.data?.items) {
        setManagedUsers(res.data.data.items)
      }
    } catch {
      // ignore
    } finally {
      setIsLoadingUsers(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [isAdmin])

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    toast.success(`${label} copied to clipboard`)
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword.length < 8) {
      toast.error('New password must be at least 8 characters')
      return
    }

    setIsChanging(true)
    try {
      await apiClient.put('/auth/me/password', {
        current_password: currentPassword,
        new_password: newPassword,
      })
      toast.success('Password updated successfully')
      setCurrentPassword('')
      setNewPassword('')
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to update password')
    } finally {
      setIsChanging(false)
    }
  }

  // Submit Feature Access Request (Normal User)
  const handleSubmitFeatureRequest = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFeatureToRequest) return
    if (requestJustification.trim().length < 10) {
      toast.error('Please enter a detailed justification (at least 10 characters).')
      return
    }

    setIsSubmittingRequest(true)
    try {
      const res = await apiClient.post('/feature-approvals/requests', {
        feature_key: selectedFeatureToRequest.key,
        justification: requestJustification.trim(),
      })
      toast.success(res.data?.message || 'Feature request submitted to Super Admin.')
      setSelectedFeatureToRequest(null)
      setRequestJustification('')
      await loadData()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to submit feature request')
    } finally {
      setIsSubmittingRequest(false)
    }
  }

  // Send Direct Message to Super Admin (Normal User)
  const handleSendContactAdmin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!contactSubject.trim() || !contactMessage.trim()) {
      toast.error('Please provide a subject and message.')
      return
    }

    setIsSendingMessage(true)
    try {
      const res = await apiClient.post('/feature-approvals/contact', {
        subject: contactSubject.trim(),
        message: contactMessage.trim(),
      })
      toast.success(res.data?.message || 'Message sent to Super Admin.')
      setContactSubject('')
      setContactMessage('')
      await loadData()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to send message')
    } finally {
      setIsSendingMessage(false)
    }
  }

  // Admin: Approve Request
  const handleApproveRequest = async (requestId: string) => {
    setIsProcessingApproval(true)
    try {
      const res = await apiClient.post(`/feature-approvals/admin/requests/${requestId}/approve`, {
        admin_notes: adminNotes.trim() || 'Approved by Super Admin.',
      })
      toast.success(res.data?.message || 'Feature approved successfully!')
      setReviewingRequest(null)
      setAdminNotes('')
      await loadData()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to approve request')
    } finally {
      setIsProcessingApproval(false)
    }
  }

  // Admin: Reject Request
  const handleRejectRequest = async (requestId: string) => {
    setIsProcessingApproval(true)
    try {
      const res = await apiClient.post(`/feature-approvals/admin/requests/${requestId}/reject`, {
        admin_notes: adminNotes.trim() || 'Declined under current compliance tier.',
      })
      toast.success(res.data?.message || 'Feature request rejected.')
      setReviewingRequest(null)
      setAdminNotes('')
      await loadData()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to reject request')
    } finally {
      setIsProcessingApproval(false)
    }
  }

  // Admin: Reply to Message
  const handleSendAdminReply = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!replyingToMessage || !adminReplyText.trim()) return

    setIsSubmittingReply(true)
    try {
      const res = await apiClient.post(
        `/feature-approvals/admin/messages/${replyingToMessage.id}/reply`,
        {
          reply: adminReplyText.trim(),
        }
      )
      toast.success(res.data?.message || 'Reply sent to user.')
      setReplyingToMessage(null)
      setAdminReplyText('')
      await loadData()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to send reply')
    } finally {
      setIsSubmittingReply(false)
    }
  }

  // Admin: Change User Role
  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      await apiClient.put(`/users/${userId}`, { role: newRole })
      toast.success(`Role updated to ${newRole.toUpperCase()}`)
      setManagedUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
      )
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to update user role')
    }
  }

  // Admin: Toggle User Active Status (Lock/Unlock)
  const handleToggleUserActive = async (userId: string, currentActive: boolean) => {
    try {
      await apiClient.put(`/users/${userId}`, { is_active: !currentActive })
      toast.success(`User account ${!currentActive ? 'activated' : 'locked'}`)
      setManagedUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, is_active: !currentActive } : u))
      )
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to update user status')
    }
  }

  // Admin: Create User
  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newUserPassword.length < 8) {
      toast.error('Password must be at least 8 characters.')
      return
    }

    setIsCreatingUser(true)
    try {
      await apiClient.post('/users', {
        email: newUserEmail.trim(),
        username: newUserName.trim(),
        display_name: newUserDisplayName.trim() || newUserName.trim(),
        password: newUserPassword,
        role: newUserRole,
      })
      toast.success(`User ${newUserEmail} created successfully.`)
      setShowAddUserModal(false)
      setNewUserEmail('')
      setNewUserName('')
      setNewUserDisplayName('')
      setNewUserPassword('')
      setNewUserRole('analyst')
      fetchManagedUsers()
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to create user')
    } finally {
      setIsCreatingUser(false)
    }
  }

  const pendingApprovalsCount = adminRequests.filter((r) => r.status === 'pending').length
  const unreadMessagesCount = adminMessages.filter((m) => m.status === 'unread').length

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-navy-700/60">
        <div>
          <h1 className="text-2xl font-black text-slate-100 flex items-center gap-2">
            <Settings className="w-6 h-6 text-accent-cyan" />
            <span>Enterprise Security & System Control Hub</span>
          </h1>
          <p className="text-slate-400 text-xs mt-1 font-mono">
            {isAdmin
              ? 'Super Admin privileged controls: user role governance, approval hub, and defense telemetry.'
              : 'Analyst portal: profile settings, feature requests, and Super Admin communications desk.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={isAdmin ? 'success' : 'outline'}>
            {user?.role?.toUpperCase() || 'ANALYST'}
          </Badge>
          <Badge variant="info">SOC2 / ISO-27001</Badge>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          NAVIGATION TABS
      ───────────────────────────────────────────────────────────── */}
      <div className="flex border-b border-navy-700 space-x-2 overflow-x-auto pb-1">
        <button
          onClick={() => setActiveTab('profile')}
          className={cn(
            'px-4 py-2 text-xs font-semibold rounded-lg flex items-center gap-2 transition-all',
            activeTab === 'profile'
              ? 'bg-accent-blue/15 text-accent-blue border-b-2 border-accent-blue'
              : 'text-slate-400 hover:text-white hover:bg-navy-800'
          )}
        >
          <User className="w-4 h-4" />
          <span>My Profile & Credentials</span>
        </button>

        <button
          onClick={() => setActiveTab('features')}
          className={cn(
            'px-4 py-2 text-xs font-semibold rounded-lg flex items-center gap-2 transition-all',
            activeTab === 'features'
              ? 'bg-accent-blue/15 text-accent-blue border-b-2 border-accent-blue'
              : 'text-slate-400 hover:text-white hover:bg-navy-800'
          )}
        >
          <Sparkles className="w-4 h-4" />
          <span>Feature Access & Grants</span>
          {myRequests.some((r) => r.status === 'approved') && (
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('contact')}
          className={cn(
            'px-4 py-2 text-xs font-semibold rounded-lg flex items-center gap-2 transition-all',
            activeTab === 'contact'
              ? 'bg-accent-blue/15 text-accent-blue border-b-2 border-accent-blue'
              : 'text-slate-400 hover:text-white hover:bg-navy-800'
          )}
        >
          <Mail className="w-4 h-4" />
          <span>Contact Super Admin</span>
          {myMessages.some((m) => m.admin_reply) && (
            <span className="w-2 h-2 rounded-full bg-accent-cyan" />
          )}
        </button>

        {/* SUPER ADMIN CONSOLE TAB (ONLY VISIBLE FOR ADMINS) */}
        {isAdmin && (
          <button
            onClick={() => setActiveTab('approvals')}
            className={cn(
              'px-4 py-2 text-xs font-bold rounded-lg flex items-center gap-2 transition-all ml-auto',
              activeTab === 'approvals'
                ? 'bg-purple-500/20 text-purple-300 border-b-2 border-purple-400'
                : 'text-purple-400 hover:text-purple-300 hover:bg-purple-950/40'
            )}
          >
            <ShieldAlert className="w-4 h-4 text-purple-400" />
            <span>Super Admin Command Desk</span>
            {pendingApprovalsCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-amber-500 text-black font-bold">
                {pendingApprovalsCount}
              </span>
            )}
            {unreadMessagesCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-accent-cyan text-black font-bold">
                {unreadMessagesCount} msgs
              </span>
            )}
          </button>
        )}
      </div>

      {/* ─────────────────────────────────────────────────────────────
          TAB 1: USER PROFILE & CREDENTIALS
      ───────────────────────────────────────────────────────────── */}
      {activeTab === 'profile' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="border-navy-700 bg-navy-800 shadow-xl md:col-span-1">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <User className="w-4 h-4 text-accent-blue" />
                <span>Analyst Identity</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs font-mono">
              <div className="bg-navy-900 p-2.5 rounded-lg border border-navy-700/70">
                <span className="text-slate-500 block text-[10px] uppercase">Display Name</span>
                <span className="text-slate-100 font-bold font-sans text-sm">
                  {user?.display_name || user?.username || 'SOC Analyst'}
                </span>
              </div>
              <div className="bg-navy-900 p-2.5 rounded-lg border border-navy-700/70">
                <span className="text-slate-500 block text-[10px] uppercase">Email</span>
                <span className="text-slate-200 font-bold truncate block">
                  {user?.email || 'analyst@phishguard.local'}
                </span>
              </div>
              <div className="bg-navy-900 p-2.5 rounded-lg border border-navy-700/70">
                <span className="text-slate-500 block text-[10px] uppercase">Assigned RBAC</span>
                <Badge variant={isAdmin ? 'success' : 'info'}>
                  {user?.role?.toUpperCase() || 'ANALYST'}
                </Badge>
              </div>
              <div className="bg-navy-900 p-2.5 rounded-lg border border-navy-700/70">
                <span className="text-slate-500 block text-[10px] uppercase">Tenant Org ID</span>
                <span className="text-slate-300 truncate block text-[11px]">
                  {user?.organization_id || 'Primary Tenant'}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Change Password */}
          <Card className="border-navy-700 bg-navy-800 shadow-xl md:col-span-2">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Lock className="w-4 h-4 text-accent-cyan" />
                <span>Account Authentication & Argon2id Password</span>
              </CardTitle>
              <p className="text-xs text-slate-400">
                Update your private credentials. Passwords are encrypted using Argon2id with 64MB memory hardness.
              </p>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleChangePassword} className="space-y-4 max-w-md text-xs">
                <div>
                  <label className="block text-slate-400 font-mono mb-1">Current Password</label>
                  <input
                    type="password"
                    required
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="w-full bg-navy-900 border border-navy-600 rounded-lg p-2.5 text-slate-100 focus:outline-none focus:border-accent-blue"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 font-mono mb-1">New Password (8+ characters)</label>
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-navy-900 border border-navy-600 rounded-lg p-2.5 text-slate-100 focus:outline-none focus:border-accent-blue"
                  />
                </div>
                <Button type="submit" size="sm" isLoading={isChanging}>
                  Update Password
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          TAB 2: FEATURE ACCESS & APPROVALS (FOR NORMAL USERS)
      ───────────────────────────────────────────────────────────── */}
      {activeTab === 'features' && (
        <div className="space-y-6">
          <div className="bg-navy-850 border border-navy-700 p-5 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-accent-cyan" />
                <span>Feature Governance & Privilege Grants</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Advanced and sensitive forensic capabilities require explicit Super Admin approval before activation.
              </p>
            </div>
            {isAdmin ? (
              <Badge variant="success">SUPER ADMIN: ALL CAPABILITIES UNLOCKED</Badge>
            ) : (
              <Badge variant="outline">ROLE: {user?.role?.toUpperCase() || 'ANALYST'}</Badge>
            )}
          </div>

          {/* Feature Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((feat) => {
              const isUnlocked = feat.can_access
              const isPending = feat.status === 'pending'
              const isApproved = feat.status === 'approved'

              return (
                <div
                  key={feat.key}
                  className={cn(
                    'p-5 rounded-2xl border transition-all flex flex-col justify-between shadow-xl',
                    isUnlocked
                      ? 'bg-navy-800/90 border-navy-600 hover:border-accent-cyan/60'
                      : 'bg-navy-900/90 border-navy-700/80 opacity-90'
                  )}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-navy-950 border border-navy-700 text-slate-400">
                        {feat.category}
                      </span>
                      {isUnlocked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                          <CheckCircle className="w-3.5 h-3.5" />
                          <span>{isApproved ? 'Approved by Admin' : 'Active'}</span>
                        </span>
                      ) : isPending ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30 animate-pulse">
                          <Clock className="w-3.5 h-3.5" />
                          <span>Pending Admin Approval</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-400 bg-navy-950 px-2 py-0.5 rounded border border-navy-700">
                          <Lock className="w-3.5 h-3.5 text-rose-400" />
                          <span>Locked</span>
                        </span>
                      )}
                    </div>

                    <h3 className="text-sm font-bold text-white mb-1.5">{feat.name}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed mb-4">
                      {feat.description}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-navy-700/60 mt-auto">
                    {isUnlocked ? (
                      <div className="text-xs text-emerald-400 flex items-center gap-1.5 font-medium">
                        <Check className="w-4 h-4" />
                        <span>Ready to use across console</span>
                      </div>
                    ) : isPending ? (
                      <div className="text-xs text-amber-400/90 font-mono">
                        Awaiting Super Admin decision...
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        className="w-full text-xs flex items-center justify-center gap-1.5"
                        onClick={() => setSelectedFeatureToRequest(feat)}
                      >
                        <Key className="w-3.5 h-3.5 text-accent-cyan" />
                        <span>Request Super Admin Approval</span>
                      </Button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* User's Request History */}
          <div className="mt-8">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-accent-cyan" />
              <span>My Feature Requests & Approval Status History</span>
            </h3>

            {myRequests.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-navy-900 rounded-xl border border-navy-800">
                You have not submitted any feature requests yet.
              </div>
            ) : (
              <div className="space-y-2.5">
                {myRequests.map((req) => (
                  <div
                    key={req.id}
                    className="p-3.5 bg-navy-900/80 rounded-xl border border-navy-700 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-xs text-white">{req.feature_name}</span>
                        <span
                          className={cn(
                            'text-[10px] font-mono px-2 py-0.5 rounded font-semibold',
                            req.status === 'approved' &&
                              'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
                            req.status === 'pending' &&
                              'bg-amber-500/20 text-amber-400 border border-amber-500/30',
                            req.status === 'rejected' &&
                              'bg-red-500/20 text-red-400 border border-red-500/30'
                          )}
                        >
                          {req.status.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        <strong>Justification:</strong> &ldquo;{req.justification}&rdquo;
                      </p>
                      {req.admin_notes && (
                        <p className="text-[11px] text-accent-cyan mt-1">
                          <strong>Admin Feedback:</strong> {req.admin_notes}
                        </p>
                      )}
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {new Date(req.created_at).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Request Modal */}
          {selectedFeatureToRequest && (
            <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in fade-in">
                <div className="flex items-center justify-between pb-2 border-b border-navy-700">
                  <div className="flex items-center gap-2 text-white font-bold text-base">
                    <Key className="w-5 h-5 text-accent-cyan" />
                    <span>Request Feature Activation</span>
                  </div>
                  <button
                    onClick={() => setSelectedFeatureToRequest(null)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-accent-cyan">
                    {selectedFeatureToRequest.name}
                  </h4>
                  <p className="text-xs text-slate-400 mt-1">
                    {selectedFeatureToRequest.description}
                  </p>
                </div>

                <form onSubmit={handleSubmitFeatureRequest} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Business Justification (Required for Super Admin Approval)
                    </label>
                    <textarea
                      required
                      rows={4}
                      value={requestJustification}
                      onChange={(e) => setRequestJustification(e.target.value)}
                      placeholder="Explain why your role requires this feature (e.g. SOC investigation escalation, threat hunt project, incident triage)..."
                      className="w-full bg-navy-950 border border-navy-700 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-accent-blue resize-none"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedFeatureToRequest(null)}
                    >
                      Cancel
                    </Button>
                    <Button type="submit" size="sm" isLoading={isSubmittingRequest}>
                      Submit to Super Admin
                    </Button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          TAB 3: CONTACT SUPER ADMIN (FOR NORMAL USERS)
      ───────────────────────────────────────────────────────────── */}
      {activeTab === 'contact' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="border-navy-700 bg-navy-800 shadow-xl">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2">
                <Mail className="w-5 h-5 text-accent-cyan" />
                <span>Contact Super Admin Desk</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Directly communicate with your enterprise security administration for account elevation, feature inquiries, or security escalations.
              </p>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSendContactAdmin} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Subject
                  </label>
                  <input
                    type="text"
                    required
                    value={contactSubject}
                    onChange={(e) => setContactSubject(e.target.value)}
                    placeholder="e.g. Permission elevation for BEC wire incident investigation"
                    className="w-full bg-navy-900 border border-navy-700 rounded-lg p-2.5 text-xs text-slate-100 focus:outline-none focus:border-accent-blue"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Detailed Message
                  </label>
                  <textarea
                    required
                    rows={5}
                    value={contactMessage}
                    onChange={(e) => setContactMessage(e.target.value)}
                    placeholder="Describe your inquiry or requirement in detail. Super Admin will review and respond directly to your account console..."
                    className="w-full bg-navy-900 border border-navy-700 rounded-lg p-3 text-xs text-slate-100 focus:outline-none focus:border-accent-blue resize-none"
                  />
                </div>

                <Button type="submit" size="sm" className="w-full" isLoading={isSendingMessage}>
                  <Send className="w-4 h-4 mr-1.5" />
                  <span>Dispatch Message to Super Admin</span>
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Sent Inquiries & Super Admin Replies */}
          <Card className="border-navy-700 bg-navy-800 shadow-xl">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-accent-blue" />
                <span>Inquiry History & Super Admin Replies</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {myMessages.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No communications logged with Super Admin.
                </div>
              ) : (
                <div className="space-y-3 max-h-[450px] overflow-y-auto pr-1">
                  {myMessages.map((msg) => (
                    <div
                      key={msg.id}
                      className="p-3.5 bg-navy-900 rounded-xl border border-navy-700/80 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-white">{msg.subject}</span>
                        <span
                          className={cn(
                            'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase',
                            msg.status === 'replied'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-navy-950 text-slate-400 border border-navy-700'
                          )}
                        >
                          {msg.status}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed font-sans">
                        {msg.message}
                      </p>

                      {msg.admin_reply && (
                        <div className="mt-2.5 p-3 rounded-lg bg-navy-950 border border-accent-blue/30 space-y-1">
                          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-accent-cyan">
                            <UserCheck className="w-3.5 h-3.5" />
                            <span>Super Admin Response:</span>
                          </div>
                          <p className="text-xs text-slate-200">{msg.admin_reply}</p>
                        </div>
                      )}

                      <div className="text-[10px] font-mono text-slate-500 pt-1">
                        Dispatched: {new Date(msg.created_at).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          TAB 4: SUPER ADMIN COMMAND DESK (SUPER ADMIN EXCLUSIVE)
      ───────────────────────────────────────────────────────────── */}
      {isAdmin && activeTab === 'approvals' && (
        <div className="space-y-6">
          {/* Sub-navigation inside Super Admin Desk */}
          <div className="flex items-center gap-2 border-b border-navy-700 pb-2">
            <button
              onClick={() => setAdminSubTab('users')}
              className={cn(
                'px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all',
                adminSubTab === 'users'
                  ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40 shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-navy-800'
              )}
            >
              <Users className="w-3.5 h-3.5" />
              <span>User & Role Governance ({managedUsers.length})</span>
            </button>

            <button
              onClick={() => setAdminSubTab('approvals')}
              className={cn(
                'px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all',
                adminSubTab === 'approvals'
                  ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40 shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-navy-800'
              )}
            >
              <Key className="w-3.5 h-3.5" />
              <span>Feature Access Approvals</span>
              {pendingApprovalsCount > 0 && (
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
              )}
            </button>

            <button
              onClick={() => setAdminSubTab('messages')}
              className={cn(
                'px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all',
                adminSubTab === 'messages'
                  ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40 shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-navy-800'
              )}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>User Inquiries Desk ({adminMessages.length})</span>
            </button>

            <button
              onClick={() => setAdminSubTab('policies')}
              className={cn(
                'px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all',
                adminSubTab === 'policies'
                  ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40 shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-navy-800'
              )}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Perimeter Defense Policies & Webhooks</span>
            </button>
          </div>

          {/* SUB-TAB 1: USER & ROLE MANAGEMENT */}
          {adminSubTab === 'users' && (
            <Card className="border-navy-700 bg-navy-800 shadow-xl">
              <CardHeader className="pb-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Users className="w-5 h-5 text-purple-400" />
                      <span>Organization Users & RBAC Role Management</span>
                    </CardTitle>
                    <p className="text-xs text-slate-400 mt-1">
                      Promote or demote user roles, manage authentication statuses, and enforce tenant access limits.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button size="sm" onClick={() => setShowAddUserModal(true)}>
                      <UserPlus className="w-4 h-4 mr-1.5" />
                      <span>Add New SOC User</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={fetchManagedUsers}
                      isLoading={isLoadingUsers}
                    >
                      <RefreshCw className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto rounded-xl border border-navy-700">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-navy-900 border-b border-navy-700 text-slate-400 uppercase font-mono text-[10px]">
                      <tr>
                        <th className="py-3 px-4">User</th>
                        <th className="py-3 px-4">Email</th>
                        <th className="py-3 px-4">Role Privileges</th>
                        <th className="py-3 px-4">Account Status</th>
                        <th className="py-3 px-4">Last Activity</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-700/60 font-mono">
                      {managedUsers.map((u) => (
                        <tr key={u.id} className="hover:bg-navy-750/50 transition-colors">
                          <td className="py-3.5 px-4 font-bold text-white font-sans">
                            {u.display_name || u.username}
                          </td>
                          <td className="py-3.5 px-4 text-slate-300">{u.email}</td>
                          <td className="py-3.5 px-4">
                            <select
                              value={u.role}
                              onChange={(e) => handleRoleChange(u.id, e.target.value)}
                              className="bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-accent-blue"
                            >
                              <option value="viewer">Viewer (Read Only)</option>
                              <option value="analyst">Analyst (SOC Tier-1/2)</option>
                              <option value="security_admin">Security Admin</option>
                              <option value="super_admin">Super Admin</option>
                            </select>
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={cn(
                                'text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase',
                                u.is_active
                                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-red-500/20 text-red-400 border border-red-500/30'
                              )}
                            >
                              {u.is_active ? 'ACTIVE' : 'LOCKED'}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400">
                            {u.last_login_at
                              ? new Date(u.last_login_at).toLocaleDateString()
                              : 'No login'}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              className={cn(
                                'text-xs',
                                u.is_active
                                  ? 'text-amber-400 hover:text-amber-300 hover:bg-amber-500/10'
                                  : 'text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10'
                              )}
                              onClick={() => handleToggleUserActive(u.id, u.is_active)}
                            >
                              {u.is_active ? 'Lockout Account' : 'Activate User'}
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* SUB-TAB 2: FEATURE APPROVALS QUEUE */}
          {adminSubTab === 'approvals' && (
            <Card className="border-navy-700 bg-navy-800 shadow-xl">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <UserCheck className="w-5 h-5 text-purple-400" />
                    <span>Feature Access Authorization Queue</span>
                  </div>
                  <Badge variant="outline">Super Admin Authorization Gate</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {adminRequests.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No feature access requests submitted by users.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {adminRequests.map((req) => (
                      <div
                        key={req.id}
                        className={cn(
                          'p-4 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all',
                          req.status === 'pending'
                            ? 'bg-navy-900 border-amber-500/40 shadow-md'
                            : 'bg-navy-900/60 border-navy-700/60'
                        )}
                      >
                        <div className="space-y-1 max-w-2xl">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-bold text-sm text-white">{req.feature_name}</span>
                            <span
                              className={cn(
                                'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase',
                                req.status === 'approved' &&
                                  'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
                                req.status === 'pending' &&
                                  'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse',
                                req.status === 'rejected' &&
                                  'bg-red-500/20 text-red-400 border border-red-500/30'
                              )}
                            >
                              {req.status}
                            </span>
                          </div>
                          <div className="text-xs text-slate-300">
                            Requested by: <strong className="text-accent-cyan">{req.user_name}</strong>{' '}
                            <span className="text-slate-500 font-mono">({req.user_email})</span>
                          </div>
                          <p className="text-xs text-slate-300 bg-navy-950 p-2.5 rounded-lg border border-navy-800">
                            &ldquo;{req.justification}&rdquo;
                          </p>
                          {req.admin_notes && (
                            <p className="text-xs text-purple-300">
                              <strong>Admin Note:</strong> {req.admin_notes}
                            </p>
                          )}
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          {req.status === 'pending' ? (
                            <Button
                              size="sm"
                              className="bg-emerald-600 hover:bg-emerald-500 text-white"
                              onClick={() => setReviewingRequest(req)}
                            >
                              <Check className="w-3.5 h-3.5 mr-1" />
                              <span>Review / Approve</span>
                            </Button>
                          ) : (
                            <div className="text-xs font-mono text-slate-500">
                              Decided: {req.reviewed_at ? new Date(req.reviewed_at).toLocaleDateString() : 'N/A'}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* SUB-TAB 3: USER INQUIRIES DESK */}
          {adminSubTab === 'messages' && (
            <Card className="border-navy-700 bg-navy-800 shadow-xl">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2">
                  <MessageSquare className="w-5 h-5 text-accent-cyan" />
                  <span>User Inquiries & Communications Desk</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {adminMessages.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No user messages received.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {adminMessages.map((msg) => (
                      <div
                        key={msg.id}
                        className="p-4 bg-navy-900 rounded-xl border border-navy-700 flex flex-col md:flex-row md:items-center justify-between gap-4"
                      >
                        <div className="space-y-1.5 max-w-2xl">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm text-white">{msg.subject}</span>
                            <span
                              className={cn(
                                'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase',
                                msg.status === 'replied'
                                  ? 'bg-emerald-500/20 text-emerald-400'
                                  : 'bg-amber-500/20 text-amber-400'
                              )}
                            >
                              {msg.status}
                            </span>
                          </div>
                          <div className="text-xs text-slate-400">
                            From: <strong className="text-slate-200">{msg.user_name}</strong>{' '}
                            <a
                              href={`mailto:${msg.user_email}`}
                              className="text-accent-cyan hover:underline font-mono inline-flex items-center gap-1 ml-1"
                            >
                              {msg.user_email}
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                          <p className="text-xs text-slate-300 bg-navy-950 p-2.5 rounded-lg border border-navy-800">
                            {msg.message}
                          </p>
                          {msg.admin_reply && (
                            <p className="text-xs text-emerald-400">
                              <strong>Your Reply:</strong> {msg.admin_reply}
                            </p>
                          )}
                        </div>

                        <div className="shrink-0 flex items-center gap-2">
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setReplyingToMessage(msg)}
                          >
                            <Send className="w-3.5 h-3.5 mr-1 text-accent-cyan" />
                            <span>{msg.admin_reply ? 'Send Another Reply' : 'Reply to User'}</span>
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* SUB-TAB 4: PERIMETER POLICIES & WEBHOOKS */}
          {adminSubTab === 'policies' && (
            <div className="space-y-6">
              <Card className="border-navy-700 bg-navy-800 shadow-xl">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="w-5 h-5 text-accent-blue" />
                      <span>Automated Quarantine Policy</span>
                    </CardTitle>
                    <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  <div className="flex items-center justify-between p-3.5 bg-navy-900 rounded-xl border border-navy-700/80">
                    <div>
                      <p className="text-xs font-bold text-slate-100">
                        Enable Automated In-Flight Quarantine
                      </p>
                      <p className="text-[11px] text-slate-400">
                        Instantly isolate or soft-delete messages exceeding the threat threshold
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      checked={autoQuarantine}
                      onChange={(e) => setAutoQuarantine(e.target.checked)}
                      className="w-4 h-4 accent-accent-blue cursor-pointer"
                    />
                  </div>

                  <div className="p-3.5 bg-navy-900 rounded-xl border border-navy-700/80 space-y-2">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-300 font-semibold">Quarantine Threshold</span>
                      <span className="text-accent-cyan font-bold text-sm">{quarantineThreshold}/100</span>
                    </div>
                    <input
                      type="range"
                      min="50"
                      max="95"
                      step="5"
                      value={quarantineThreshold}
                      onChange={(e) => setQuarantineThreshold(Number(e.target.value))}
                      className="w-full accent-accent-blue cursor-pointer"
                    />
                  </div>

                  <div className="flex justify-end pt-2">
                    <Button
                      size="sm"
                      onClick={() =>
                        toast.success('Automated quarantine defense policy updated and enforced.')
                      }
                    >
                      Apply Defense Policy
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Ingestion Webhooks */}
              <Card className="border-navy-700 bg-navy-800 shadow-xl">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-2">
                    <Server className="w-5 h-5 text-accent-cyan" />
                    <span>Enterprise Mail-Flow Webhook Endpoints</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="p-3 bg-navy-900 rounded-xl border border-navy-700/80 flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="text-[10px] font-mono uppercase text-accent-cyan font-bold block">
                        Direct MTA / Postfix Webhook
                      </span>
                      <code className="text-xs text-slate-200 font-mono truncate block mt-0.5">
                        http://localhost:8000/api/v1/webhooks/mta
                      </code>
                    </div>
                    <button
                      onClick={() => copyToClipboard('http://localhost:8000/api/v1/webhooks/mta', 'MTA Webhook URL')}
                      className="p-1.5 text-slate-400 hover:text-white hover:bg-navy-800 rounded-lg transition-colors flex-shrink-0"
                      title="Copy URL"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="p-3 bg-navy-900 rounded-xl border border-navy-700/80 flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="text-[10px] font-mono uppercase text-blue-400 font-bold block">
                        Microsoft 365 Exchange Graph Webhook
                      </span>
                      <code className="text-xs text-slate-200 font-mono truncate block mt-0.5">
                        http://localhost:8000/api/v1/webhooks/m365
                      </code>
                    </div>
                    <button
                      onClick={() => copyToClipboard('http://localhost:8000/api/v1/webhooks/m365', 'M365 Webhook URL')}
                      className="p-1.5 text-slate-400 hover:text-white hover:bg-navy-800 rounded-lg transition-colors flex-shrink-0"
                      title="Copy URL"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Admin Decision Modal */}
          {reviewingRequest && (
            <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in fade-in">
                <div className="flex items-center justify-between pb-2 border-b border-navy-700">
                  <div className="flex items-center gap-2 text-white font-bold text-base">
                    <UserCheck className="w-5 h-5 text-purple-400" />
                    <span>Super Admin Authorization Decision</span>
                  </div>
                  <button onClick={() => setReviewingRequest(null)} className="text-slate-400 hover:text-white">
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div className="bg-navy-950 p-3.5 rounded-xl border border-navy-800 space-y-1">
                  <div className="text-xs text-slate-400">
                    Applicant: <strong className="text-white">{reviewingRequest.user_name}</strong> ({reviewingRequest.user_email})
                  </div>
                  <div className="text-xs text-slate-400">
                    Feature: <strong className="text-accent-cyan">{reviewingRequest.feature_name}</strong>
                  </div>
                  <p className="text-xs text-slate-300 mt-2 italic">
                    &ldquo;{reviewingRequest.justification}&rdquo;
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Super Admin Feedback Notes (Optional)
                  </label>
                  <textarea
                    rows={3}
                    value={adminNotes}
                    onChange={(e) => setAdminNotes(e.target.value)}
                    placeholder="e.g. Approved for Incident Triage Q4. Access expires in 90 days."
                    className="w-full bg-navy-950 border border-navy-700 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-accent-blue resize-none"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={isProcessingApproval}
                    onClick={() => handleRejectRequest(reviewingRequest.id)}
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                  >
                    <XCircle className="w-4 h-4 mr-1" />
                    <span>Reject Request</span>
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    isLoading={isProcessingApproval}
                    onClick={() => handleApproveRequest(reviewingRequest.id)}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    <CheckCircle className="w-4 h-4 mr-1" />
                    <span>Authorize & Unlock Feature</span>
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Admin Reply Modal */}
          {replyingToMessage && (
            <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in fade-in">
                <div className="flex items-center justify-between pb-2 border-b border-navy-700">
                  <div className="flex items-center gap-2 text-white font-bold text-base">
                    <Send className="w-5 h-5 text-accent-cyan" />
                    <span>Reply to {replyingToMessage.user_name}</span>
                  </div>
                  <button onClick={() => setReplyingToMessage(null)} className="text-slate-400 hover:text-white">
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <div className="bg-navy-950 p-3 rounded-xl border border-navy-800 text-xs text-slate-300">
                  <strong>Subject:</strong> {replyingToMessage.subject}
                  <p className="mt-1 text-slate-400 italic">&ldquo;{replyingToMessage.message}&rdquo;</p>
                </div>

                <form onSubmit={handleSendAdminReply} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Your Response
                    </label>
                    <textarea
                      required
                      rows={4}
                      value={adminReplyText}
                      onChange={(e) => setAdminReplyText(e.target.value)}
                      placeholder="Type your response to the user..."
                      className="w-full bg-navy-950 border border-navy-700 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-accent-blue resize-none"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setReplyingToMessage(null)}
                    >
                      Cancel
                    </Button>
                    <Button type="submit" size="sm" isLoading={isSubmittingReply}>
                      Send Response
                    </Button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* Add User Modal */}
          {showAddUserModal && (
            <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
                <div className="flex items-center justify-between pb-2 border-b border-navy-700">
                  <div className="flex items-center gap-2 text-white font-bold text-base">
                    <UserPlus className="w-5 h-5 text-purple-400" />
                    <span>Create Organization User</span>
                  </div>
                  <button onClick={() => setShowAddUserModal(false)} className="text-slate-400 hover:text-white">
                    <X className="w-5 h-5" />
                  </button>
                </div>

                <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">Work Email</label>
                    <input
                      type="email"
                      required
                      placeholder="analyst@enterprise.com"
                      value={newUserEmail}
                      onChange={(e) => setNewUserEmail(e.target.value)}
                      className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Username</label>
                      <input
                        type="text"
                        required
                        placeholder="analyst_jane"
                        value={newUserName}
                        onChange={(e) => setNewUserName(e.target.value)}
                        className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 font-semibold mb-1">Full Name</label>
                      <input
                        type="text"
                        placeholder="Jane Doe"
                        value={newUserDisplayName}
                        onChange={(e) => setNewUserDisplayName(e.target.value)}
                        className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">Temporary Password (8+)</label>
                    <input
                      type="password"
                      required
                      placeholder="Minimum 8 characters..."
                      value={newUserPassword}
                      onChange={(e) => setNewUserPassword(e.target.value)}
                      className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">Initial Role</label>
                    <select
                      value={newUserRole}
                      onChange={(e) => setNewUserRole(e.target.value)}
                      className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                    >
                      <option value="viewer">Viewer (Read-only)</option>
                      <option value="analyst">Analyst (SOC Tier-1/2)</option>
                      <option value="security_admin">Security Admin</option>
                      <option value="super_admin">Super Admin</option>
                    </select>
                  </div>

                  <div className="flex justify-end gap-2 pt-2">
                    <Button type="button" variant="ghost" size="sm" onClick={() => setShowAddUserModal(false)}>
                      Cancel
                    </Button>
                    <Button type="submit" size="sm" isLoading={isCreatingUser}>
                      Provision User
                    </Button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
