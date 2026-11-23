import { Metadata } from 'next'
import { AuthLayoutView } from '@/components/auth/AuthLayoutView'

export const metadata: Metadata = {
  title: 'Create Account — Phishing EML Analyzer',
  description: 'Provision new analyst credentials for Phishing EML Analyzer',
}

export default function RegisterPage() {
  return <AuthLayoutView initialMode="register" />
}
