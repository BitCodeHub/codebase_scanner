import { useState, useCallback } from 'react'
import { Upload, X, File, AlertCircle, CheckCircle } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
  maxFiles?: number
  maxSize?: number // in MB
  acceptedTypes?: string[]
  className?: string
}

interface UploadedFile {
  file: File
  id: string
  status: 'pending' | 'uploading' | 'success' | 'error'
  progress: number
  error?: string
}

export default function FileUpload({
  onFilesSelected,
  maxFiles = 10,
  maxSize = 50,
  acceptedTypes = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.rb', '.go'],
  className = ''
}: FileUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([])
  const [isDragOver, setIsDragOver] = useState(false)

  const generateId = () => Math.random().toString(36).substr(2, 9)

  const validateFile = (file: File): string | null => {
    // Check file size
    if (file.size > maxSize * 1024 * 1024) {
      return `File size exceeds ${maxSize}MB limit`
    }

    // Check file type
    const extension = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!acceptedTypes.includes(extension)) {
      return `File type ${extension} is not supported`
    }

    return null
  }

  const handleFiles = useCallback((fileList: FileList) => {
    const newFiles: UploadedFile[] = []
    const validFiles: File[] = []

    Array.from(fileList).forEach(file => {
      if (files.length + newFiles.length >= maxFiles) {
        return
      }

      const error = validateFile(file)
      const uploadedFile: UploadedFile = {
        file,
        id: generateId(),
        status: error ? 'error' : 'pending',
        progress: 0,
        error: error || undefined
      }

      newFiles.push(uploadedFile)
      if (!error) {
        validFiles.push(file)
      }
    })

    setFiles(prev => [...prev, ...newFiles])
    if (validFiles.length > 0) {
      onFilesSelected(validFiles)
    }
  }, [files.length, maxFiles, maxSize, acceptedTypes, onFilesSelected])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
    handleFiles(e.dataTransfer.files)
  }, [handleFiles])

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      handleFiles(e.target.files)
    }
  }, [handleFiles])

  const removeFile = useCallback((id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id))
  }, [])

  const clearAll = useCallback(() => {
    setFiles([])
  }, [])

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Upload Area */}
      <div
        className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
          isDragOver
            ? 'border-blue-400 bg-blue-50'
            : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          type="file"
          multiple
          accept={acceptedTypes.join(',')}
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={files.length >= maxFiles}
        />
        
        <div className="space-y-3">
          <div className="mx-auto w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center">
            <Upload className="h-8 w-8 text-gray-400" />
          </div>
          
          <div>
            <p className="text-lg font-medium text-gray-900">
              Drop files here or click to upload
            </p>
            <p className="text-sm text-gray-500 mt-1">
              Supports: {acceptedTypes.join(', ')} • Max {maxFiles} files • {maxSize}MB each
            </p>
          </div>
          
          {files.length >= maxFiles && (
            <p className="text-sm text-red-600">
              Maximum number of files reached
            </p>
          )}
        </div>
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-900">
              Uploaded Files ({files.length}/{maxFiles})
            </h3>
            <button
              onClick={clearAll}
              className="text-sm text-red-600 hover:text-red-700"
            >
              Clear All
            </button>
          </div>
          
          <div className="space-y-2">
            {files.map((uploadedFile) => (
              <div
                key={uploadedFile.id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              >
                <div className="flex items-center space-x-3 flex-1">
                  <div className="flex-shrink-0">
                    {uploadedFile.status === 'error' ? (
                      <AlertCircle className="h-5 w-5 text-red-500" />
                    ) : uploadedFile.status === 'success' ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <File className="h-5 w-5 text-gray-400" />
                    )}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {uploadedFile.file.name}
                    </p>
                    <div className="flex items-center space-x-2 text-xs text-gray-500">
                      <span>{(uploadedFile.file.size / 1024 / 1024).toFixed(2)} MB</span>
                      <span>•</span>
                      <span className={`${
                        uploadedFile.status === 'error' ? 'text-red-600' :
                        uploadedFile.status === 'success' ? 'text-green-600' :
                        'text-gray-500'
                      }`}>
                        {uploadedFile.status === 'error' ? uploadedFile.error :
                         uploadedFile.status === 'success' ? 'Ready for scan' :
                         'Pending'}
                      </span>
                    </div>
                  </div>
                </div>
                
                <button
                  onClick={() => removeFile(uploadedFile.id)}
                  className="flex-shrink-0 p-1 text-gray-400 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}