import { Metadata } from 'next'
import { AuthLayoutView } from '@/components/auth/AuthLayoutView'

export const metadata: Metadata = {
  title: 'Sign In — Phishing EML Analyzer',
  description: 'Enterprise SOC analyst authentication for Phishing EML Analyzer',
}

export default function LoginPage() {
  return <AuthLayoutView initialMode="login" />
}
