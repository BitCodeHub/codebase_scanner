import React, { createContext, useContext, useState } from 'react'
import { clsx } from 'clsx'

interface TabsContextValue {
  activeTab: string
  setActiveTab: (value: string) => void
}

const TabsContext = createContext<TabsContextValue | undefined>(undefined)

interface TabsProps {
  defaultValue: string
  children: React.ReactNode
  className?: string
}

export const Tabs: React.FC<TabsProps> = ({ defaultValue, children, className }) => {
  const [activeTab, setActiveTab] = useState(defaultValue)

  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      <div className={clsx('', className)}>{children}</div>
    </TabsContext.Provider>
  )
}

interface TabsListProps {
  children: React.ReactNode
  className?: string
}

export const TabsList: React.FC<TabsListProps> = ({ children, className }) => {
  return (
    <div className={clsx('flex space-x-1 border-b', className)}>
      {children}
    </div>
  )
}

interface TabsTriggerProps {
  value: string
  children: React.ReactNode
  className?: string
}

export const TabsTrigger: React.FC<TabsTriggerProps> = ({ value, children, className }) => {
  const context = useContext(TabsContext)
  if (!context) throw new Error('TabsTrigger must be used within Tabs')

  const isActive = context.activeTab === value

  return (
    <button
      className={clsx(
        'px-3 py-2 font-medium text-sm rounded-t-lg transition-colors',
        isActive 
          ? 'bg-white text-blue-600 border-b-2 border-blue-600' 
          : 'text-gray-600 hover:text-gray-900',
        className
      )}
      onClick={() => context.setActiveTab(value)}
    >
      {children}
    </button>
  )
}

interface TabsContentProps {
  value: string
  children: React.ReactNode
  className?: string
}

export const TabsContent: React.FC<TabsContentProps> = ({ value, children, className }) => {
  const context = useContext(TabsContext)
  if (!context) throw new Error('TabsContent must be used within Tabs')

  if (context.activeTab !== value) return null

  return <div className={clsx('mt-4', className)}>{children}</div>
}