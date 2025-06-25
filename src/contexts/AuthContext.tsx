"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import axios from "axios"

interface User {
  id: string
  fullName: string
  email: string
  avatar?: string
  lastLogin?: string
}

interface AuthContextType {
  user: User | null
  login: (email: string, password: string) => Promise<void>
  register: (fullName: string, email: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000"

// Configure axios defaults
axios.defaults.baseURL = API_URL

// Add token to requests
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem("token")
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle token expiration
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      localStorage.removeItem("token")
      localStorage.removeItem("isLogging")
      window.location.href = "/login"
    }
    return Promise.reject(error)
  },
)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem("token")
    const isLogging = localStorage.getItem("isLogging") === "true"

    if (token && isLogging) {
      fetchUser()
    } else {
      setLoading(false)
    }
  }, [])

  const fetchUser = async () => {
    try {
      const response = await axios.get("/api/profile")
      setUser(response.data)
      localStorage.setItem("isLogging", "true")
    } catch (error) {
      console.error("Failed to fetch user:", error)
      localStorage.removeItem("token")
      localStorage.removeItem("isLogging")
    } finally {
      setLoading(false)
    }
  }

  const login = async (email: string, password: string) => {
    const response = await axios.post("/api/login", { email, password })
    const { token, user } = response.data

    localStorage.setItem("token", token)
    localStorage.setItem("isLogging", "true")
    setUser(user)
  }

  const register = async (fullName: string, email: string, password: string) => {
    const response = await axios.post("/api/register", { fullName, email, password })
    const { token, user } = response.data

    localStorage.setItem("token", token)
    localStorage.setItem("isLogging", "true")
    setUser(user)
  }

  const logout = () => {
    localStorage.removeItem("token")
    localStorage.removeItem("isLogging")
    setUser(null)
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        register,
        logout,
        loading,
        isAuthenticated: !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
