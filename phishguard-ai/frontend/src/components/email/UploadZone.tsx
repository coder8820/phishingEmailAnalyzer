'use client'

import React, { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { UploadCloud, FileCode, AlertCircle, FileCheck } from 'lucide-react'
import { cn } from '@/lib/utils'

interface UploadZoneProps {
  onFileSelect: (file: File) => void
  disabled?: boolean
}

export function UploadZone({ onFileSelect, disabled }: UploadZoneProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const onDrop = useCallback(
    (acceptedFiles: File[], fileRejections: any[]) => {
      setErrorMsg(null)
      if (fileRejections.length > 0) {
        const rejection = fileRejections[0]
        if (rejection.file.size > 25 * 1024 * 1024) {
          setErrorMsg('File exceeds maximum upload size (25MB limit enforced)')
        } else {
          setErrorMsg('Invalid file format. Only RFC 822 .eml files are accepted.')
        }
        return
      }

      if (acceptedFiles.length > 0) {
        const file = acceptedFiles[0]
        setSelectedFile(file)
        onFileSelect(file)
      }
    },
    [onFileSelect]
  )

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'message/rfc822': ['.eml'],
      'application/octet-stream': ['.eml'],
      'text/plain': ['.eml'],
    },
    maxSize: 25 * 1024 * 1024,
    multiple: false,
    disabled,
  })

  return (
    <div className="w-full">
      <div
        {...getRootProps()}
        className={cn(
          'border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 select-none',
          isDragActive
            ? 'border-accent-blue bg-accent-blue/5 scale-[1.01]'
            : isDragReject
            ? 'border-red-500 bg-red-500/5'
            : 'border-navy-600 bg-navy-850/60 hover:border-accent-blue/50 hover:bg-navy-800/80',
          disabled && 'opacity-50 cursor-not-allowed hover:border-navy-600'
        )}
      >
        <input {...getInputProps()} />
        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-accent-blue/10 border border-accent-blue/20 flex items-center justify-center text-accent-blue shadow-inner">
            {selectedFile ? (
              <FileCheck className="w-6 h-6 text-green-400" />
            ) : (
              <UploadCloud className="w-6 h-6" />
            )}
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-200">
              {selectedFile ? selectedFile.name : 'Drop .eml file here or click to browse'}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              RFC 822 email format supported • Maximum size 25MB • Zero local execution
            </p>
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-2 mt-2.5 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  )
}
