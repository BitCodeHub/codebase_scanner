import React from 'react'
import { clsx } from 'clsx'

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'secondary' | 'success' | 'warning' | 'danger'
  children: React.ReactNode
}

export const Badge: React.FC<BadgeProps> = ({ 
  variant = 'default', 
  className, 
  children, 
  ...props 
}) => {
  const variants = {
    default: 'bg-gray-100 text-gray-800',
    secondary: 'bg-blue-100 text-blue-800',
    success: 'bg-green-100 text-green-800',
    warning: 'bg-yellow-100 text-yellow-800',
    danger: 'bg-red-100 text-red-800'
  }

  return (
    <span 
      className={clsx(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
        variants[variant],
        className
      )} 
      {...props}
    >
      {children}
    </span>
  )
}