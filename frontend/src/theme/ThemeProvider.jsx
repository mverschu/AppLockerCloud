import React, { createContext, useContext, useState, useEffect, useMemo } from 'react'
import { ThemeProvider as MUIThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'

const ThemeContext = createContext()

export const useThemeMode = () => {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useThemeMode must be used within a ThemeProvider')
  }
  return context
}

const THEME_STORAGE_KEY = 'applocker_theme_mode'

export const ThemeProvider = ({ children }) => {
  const [mode, setMode] = useState(() => {
    // Load from localStorage or default to 'light'
    const savedMode = localStorage.getItem(THEME_STORAGE_KEY)
    return savedMode || 'light'
  })

  useEffect(() => {
    // Save to localStorage whenever mode changes
    localStorage.setItem(THEME_STORAGE_KEY, mode)
  }, [mode])

  const toggleColorMode = () => {
    setMode((prevMode) => (prevMode === 'light' ? 'dark' : 'light'))
  }

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode,
          ...(mode === 'dark'
            ? {
                // Dark mode palette
                background: {
                  default: '#121212',
                  paper: '#1e1e1e',
                },
              }
            : {
                // Light mode palette
                background: {
                  default: '#f5f5f5',
                  paper: '#ffffff',
                },
              }),
        },
      }),
    [mode]
  )

  const value = useMemo(
    () => ({
      mode,
      toggleColorMode,
    }),
    [mode]
  )

  return (
    <ThemeContext.Provider value={value}>
      <MUIThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </MUIThemeProvider>
    </ThemeContext.Provider>
  )
}

