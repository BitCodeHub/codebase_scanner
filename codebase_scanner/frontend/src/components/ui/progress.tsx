import React from 'react'
import { clsx } from 'clsx'

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number
  max?: number
  variant?: 'default' | 'success' | 'warning' | 'danger'
}

export const Progress: React.FC<ProgressProps> = ({ 
  value, 
  max = 100, 
  variant = 'default',
  className, 
  ...props 
}) => {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100))
  
  const variants = {
    default: 'bg-blue-600',
    success: 'bg-green-600',
    warning: 'bg-yellow-600',
    danger: 'bg-red-600'
  }

  return (
    <div 
      className={clsx('w-full bg-gray-200 rounded-full h-2.5', className)} 
      {...props}
    >
      <div 
        className={clsx('h-2.5 rounded-full transition-all duration-300', variants[variant])}
        style={{ width: `${percentage}%` }}
      />
    </div>
  )
}