import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import LoadingSpinner from '@/components/ui/LoadingSpinner'

describe('LoadingSpinner', () => {
  it('renders with default size', () => {
    const { container } = render(<LoadingSpinner />)
    const spinner = container.querySelector('.animate-spin')
    
    expect(spinner).toBeInTheDocument()
    expect(spinner).toHaveClass('h-6', 'w-6') // Default md size
  })

  it('renders with small size', () => {
    const { container } = render(<LoadingSpinner size="sm" />)
    const spinner = container.querySelector('.animate-spin')
    
    expect(spinner).toBeInTheDocument()
    expect(spinner).toHaveClass('h-4', 'w-4')
  })

  it('renders with large size', () => {
    const { container } = render(<LoadingSpinner size="lg" />)
    const spinner = container.querySelector('.animate-spin')
    
    expect(spinner).toBeInTheDocument()
    expect(spinner).toHaveClass('h-8', 'w-8')
  })

  it('applies custom className', () => {
    const customClass = 'my-custom-class'
    const { container } = render(<LoadingSpinner className={customClass} />)
    const wrapper = container.firstChild
    
    expect(wrapper).toHaveClass(customClass)
  })

  it('has proper animation classes', () => {
    const { container } = render(<LoadingSpinner />)
    const spinner = container.querySelector('.animate-spin')
    
    expect(spinner).toHaveClass('animate-spin', 'rounded-full', 'border-2', 'border-gray-300', 'border-t-blue-600')
  })
})