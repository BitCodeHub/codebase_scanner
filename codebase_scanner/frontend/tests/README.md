# Frontend Tests

This directory contains all the tests for the frontend application.

## Structure

```
tests/
├── components/          # Component tests
│   └── ui/             # UI component tests
├── utils/              # Utility function tests
├── setup.ts            # Test setup file
├── test-utils.tsx      # Common test utilities and custom render
└── README.md           # This file
```

## Running Tests

```bash
# Run all tests
npm test

# Run tests in UI mode
npm run test:ui

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm test -- --watch
```

## Writing Tests

1. **Component Tests**: Place in `tests/components/` matching the src structure
2. **Utility Tests**: Place in `tests/utils/`
3. **Use the custom render**: Import from `tests/test-utils.tsx` for components that need providers

Example test:

```tsx
import { describe, it, expect } from 'vitest'
import { render, screen } from '../test-utils'
import MyComponent from '@/components/MyComponent'

describe('MyComponent', () => {
  it('renders correctly', () => {
    render(<MyComponent />)
    expect(screen.getByText('Hello')).toBeInTheDocument()
  })
})
```

## Test Stack

- **Vitest**: Test runner
- **React Testing Library**: Component testing
- **jsdom**: DOM environment
- **@testing-library/jest-dom**: Additional matchers