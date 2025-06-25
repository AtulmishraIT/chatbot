/* eslint-disable @typescript-eslint/no-explicit-any */
"use client"

import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { useAuth } from "../contexts/AuthContext"
import { useTheme } from "../contexts/ThemeContext"
import { Sun, Moon, Monitor, User, LogOut, LogIn, UserPlus, MessageCircle, Menu, X } from "lucide-react"

function Navbar() {
  const { user, logout, isAuthenticated } = useAuth()
  const { theme, setTheme } = useTheme()
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [isThemeMenuOpen, setIsThemeMenuOpen] = useState(false)
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate("/")
    setIsMenuOpen(false)
  }

  const themeOptions = [
    { value: "light", label: "Light", icon: Sun },
    { value: "dark", label: "Dark", icon: Moon },
    { value: "system", label: "System", icon: Monitor },
  ]

  const currentThemeIcon = themeOptions.find((option) => option.value === theme)?.icon || Monitor
  const CurrentThemeIcon = currentThemeIcon

  return (
    <nav className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-50 backdrop-blur-sm bg-white/95 dark:bg-gray-900/95">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link
            to="/"
            className="flex items-center space-x-2 text-xl font-bold text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
          >
            <MessageCircle className="h-8 w-8 text-blue-600 dark:text-blue-400" />
            <span className="hidden sm:block">AI Chatbot</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-4">
            {/* Theme Selector */}
            <div className="relative">
              <button
                onClick={() => setIsThemeMenuOpen(!isThemeMenuOpen)}
                className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                title="Change theme"
              >
                <CurrentThemeIcon className="h-5 w-5 text-gray-700 dark:text-gray-300" />
              </button>

              {isThemeMenuOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-50">
                  {themeOptions.map((option) => {
                    const Icon = option.icon
                    return (
                      <button
                        key={option.value}
                        onClick={() => {
                          setTheme(option.value as any)
                          setIsThemeMenuOpen(false)
                        }}
                        className={`w-full flex items-center px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors ${
                          theme === option.value
                            ? "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20"
                            : "text-gray-700 dark:text-gray-300"
                        }`}
                      >
                        <Icon className="h-4 w-4 mr-3" />
                        {option.label}
                      </button>
                    )
                  })}
                </div>
              )}
            </div>

            {/* User Menu */}
            {isAuthenticated ? (
              <div className="flex items-center space-x-3">
                <span className="text-sm text-gray-700 dark:text-gray-300 hidden lg:block">
                  Welcome, {user?.fullName}
                </span>
                <Link
                  to="/profile"
                  className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors text-gray-700 dark:text-gray-300"
                >
                  <User className="h-4 w-4" />
                  <span className="hidden lg:block">Profile</span>
                </Link>
                <button
                  onClick={handleLogout}
                  className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-red-100 dark:bg-red-900/20 hover:bg-red-200 dark:hover:bg-red-900/30 transition-colors text-red-700 dark:text-red-400"
                >
                  <LogOut className="h-4 w-4" />
                  <span className="hidden lg:block">Logout</span>
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-3">
                <Link
                  to="/login"
                  className="flex items-center space-x-2 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-gray-700 dark:text-gray-300"
                >
                  <LogIn className="h-4 w-4" />
                  <span>Login</span>
                </Link>
                <Link
                  to="/register"
                  className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 transition-colors text-white"
                >
                  <UserPlus className="h-4 w-4" />
                  <span>Sign Up</span>
                </Link>
              </div>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              {isMenuOpen ? (
                <X className="h-6 w-6 text-gray-700 dark:text-gray-300" />
              ) : (
                <Menu className="h-6 w-6 text-gray-700 dark:text-gray-300" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-gray-200 dark:border-gray-700 py-4">
            <div className="space-y-3">
              {/* Theme Selector Mobile */}
              <div className="px-4">
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Theme</p>
                <div className="grid grid-cols-3 gap-2">
                  {themeOptions.map((option) => {
                    const Icon = option.icon
                    return (
                      <button
                        key={option.value}
                        onClick={() => {
                          setTheme(option.value as any)
                          setIsMenuOpen(false)
                        }}
                        className={`flex flex-col items-center p-3 rounded-lg transition-colors ${
                          theme === option.value
                            ? "bg-blue-100 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400"
                            : "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
                        }`}
                      >
                        <Icon className="h-5 w-5 mb-1" />
                        <span className="text-xs">{option.label}</span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* User Menu Mobile */}
              {isAuthenticated ? (
                <div className="space-y-2 px-4">
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Welcome, {user?.fullName}</p>
                  <Link
                    to="/profile"
                    onClick={() => setIsMenuOpen(false)}
                    className="flex items-center space-x-3 w-full px-4 py-3 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors text-gray-700 dark:text-gray-300"
                  >
                    <User className="h-5 w-5" />
                    <span>Profile</span>
                  </Link>
                  <button
                    onClick={handleLogout}
                    className="flex items-center space-x-3 w-full px-4 py-3 rounded-lg bg-red-100 dark:bg-red-900/20 hover:bg-red-200 dark:hover:bg-red-900/30 transition-colors text-red-700 dark:text-red-400"
                  >
                    <LogOut className="h-5 w-5" />
                    <span>Logout</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-2 px-4">
                  <Link
                    to="/login"
                    onClick={() => setIsMenuOpen(false)}
                    className="flex items-center space-x-3 w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-gray-700 dark:text-gray-300"
                  >
                    <LogIn className="h-5 w-5" />
                    <span>Login</span>
                  </Link>
                  <Link
                    to="/register"
                    onClick={() => setIsMenuOpen(false)}
                    className="flex items-center space-x-3 w-full px-4 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 transition-colors text-white"
                  >
                    <UserPlus className="h-5 w-5" />
                    <span>Sign Up</span>
                  </Link>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Click outside to close theme menu */}
      {isThemeMenuOpen && <div className="fixed inset-0 z-40" onClick={() => setIsThemeMenuOpen(false)} />}
    </nav>
  )
}

export default Navbar
