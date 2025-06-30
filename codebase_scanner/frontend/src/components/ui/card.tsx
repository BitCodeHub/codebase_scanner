import React from 'react'
import { clsx } from 'clsx'

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

export const Card: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <div className={clsx('bg-white rounded-lg shadow-md p-6', className)} {...props}>
      {children}
    </div>
  )
}

export const CardHeader: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <div className={clsx('mb-4', className)} {...props}>
      {children}
    </div>
  )
}

export const CardTitle: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <h3 className={clsx('text-lg font-semibold', className)} {...props}>
      {children}
    </h3>
  )
}

export const CardDescription: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <p className={clsx('text-sm text-gray-600', className)} {...props}>
      {children}
    </p>
  )
}

export const CardContent: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <div className={clsx('', className)} {...props}>
      {children}
    </div>
  )
}

export const CardFooter: React.FC<CardProps> = ({ className, children, ...props }) => {
  return (
    <div className={clsx('mt-4 pt-4 border-t', className)} {...props}>
      {children}
    </div>
  )
}