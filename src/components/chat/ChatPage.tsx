'use client'

import type React from 'react'
import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Send,
  Copy,
  Download,
  Lightbulb,
  MessageCircle,
  User,
  Bot,
  Check,
  AlertCircle,
  Loader2,
  Mic,
  MicOff,
} from 'lucide-react'

declare global {
  interface Window {
    SpeechRecognition: any
    webkitSpeechRecognition: any
  }
}

interface Message {
  sender: 'user' | 'bot'
  content: string
  timestamp?: Date
  id?: string
}

const PROMPT_TEMPLATES = [
  'Explain quantum computing in simple terms',
  'Write a creative story about time travel',
  'Help me plan a healthy meal for the week',
  'What are the latest trends in web development?',
  'Give me tips for improving productivity',
  'Explain the concept of machine learning',
  'How can I improve my communication skills?',
  'What are some good books to read this year?',
]

const ChatPage = () => {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [showTemplates, setShowTemplates] = useState(false)
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const messagesEndRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLTextAreaElement | null>(null)
  const { user, isAuthenticated } = useAuth()
  const navigate = useNavigate()
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [isListening, setIsListening] = useState(false)
  const [recognition, setRecognition] = useState<any>(null)
  const [speechSupported, setSpeechSupported] = useState(false)
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  // const useTemplate = (template: string) => {
  //   setSelectedTemplate(template)
  // }

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login')
      return
    }

    // Focus input on mount
    inputRef.current?.focus()
  }, [isAuthenticated, navigate])

  useEffect(() => {
      const handleOnline = () => {
        if(!navigator.onLine){
          setIsOnline(false);
        }
      }
      handleOnline();
    })
    
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    if (selectedTemplate) {
      setInput(selectedTemplate)
      setShowTemplates(false)
      inputRef.current?.focus()
      setSelectedTemplate(null)
    }
  }, [selectedTemplate])

  useEffect(() => {
    // Check if speech recognition is supported
    if (typeof window !== 'undefined') {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition

      if (SpeechRecognition) {
        setSpeechSupported(true)
        const recognitionInstance = new SpeechRecognition()

        // Configure recognition settings
        recognitionInstance.continuous = false
        recognitionInstance.interimResults = false
        recognitionInstance.lang = 'en-US'
        recognitionInstance.maxAlternatives = 1

        recognitionInstance.onstart = () => {
          console.log('Speech recognition started')
          setIsListening(true)
          setError('')
        }

        recognitionInstance.onresult = (event: any) => {
          console.log('Speech recognition result:', event)
          const transcript = event.results[0][0].transcript
          console.log('Transcript:', transcript)

          setInput((prev) => {
            const newValue = prev + (prev ? ' ' : '') + transcript
            return newValue
          })

          // Focus back to input after adding text
          setTimeout(() => {
            inputRef.current?.focus()
          }, 100)
        }

        recognitionInstance.onerror = (event: any) => {
          console.error('Speech recognition error:', event.error)
          setIsListening(false)

          let errorMessage = 'Speech recognition failed. '
          switch (event.error) {
            case 'no-speech':
              errorMessage += 'No speech was detected. Please try again.'
              break
            case 'audio-capture':
              errorMessage += 'No microphone was found. Please check your microphone.'
              break
            case 'not-allowed':
              errorMessage +=
                'Microphone access was denied. Please allow microphone access and try again.'
              break
            case 'network':
              errorMessage += 'Network error occurred. Please check your internet connection.'
              break
            case 'aborted':
              errorMessage += 'Speech recognition was aborted.'
              break
            default:
              errorMessage += 'Please try again.'
          }
          setError(errorMessage)
        }

        recognitionInstance.onend = () => {
          console.log('Speech recognition ended')
          setIsListening(false)
        }

        setRecognition(recognitionInstance)
      } else {
        console.log('Speech recognition not supported')
        setSpeechSupported(false)
      }
    }
  }, [])

  const createSession = async () => {
    try {
      const response = await axios.post('/api/chat/sessions', {
        title: input.slice(0, 50) || 'New Chat',
      })
      setSessionId(response.data._id)
      return response.data._id
    } catch (error) {
      console.error('Failed to create session:', error)
      setError('Failed to create chat session')
      return null
    }
  }

  const sendMessage = async (messageText?: string) => {
    const messageToSend = messageText || input
    if (!messageToSend.trim() || loading) return

    const newMessage: Message = {
      sender: 'user',
      content: messageToSend.trim(),
      timestamp: new Date(),
      id: Date.now().toString(),
    }

    setMessages((prev) => [...prev, newMessage])
    setInput('')
    setLoading(true)
    setError('')

    try {
      let currentSessionId = sessionId
      if (!currentSessionId) {
        currentSessionId = await createSession()
        if (!currentSessionId) {
          setLoading(false)
          return
        }
      }

      console.log('Sending message:', { prompt: messageToSend.trim(), sessionId: currentSessionId })

      const response = await axios.post('/api/chat', {
        prompt: messageToSend.trim(), // Server expects 'prompt', not 'messages'
        sessionId: currentSessionId,
      })

      console.log('Received response:', response.data)

      const botMessage: Message = {
        sender: 'bot',
        content: response.data.reply,
        timestamp: new Date(),
        id: (Date.now() + 1).toString(),
      }

      setMessages((prev) => [...prev, botMessage])
    } catch (err: any) {
      console.error('Chat error:', err)
      setError(err.response?.data?.error || 'Failed to send message. Please try again.')

      // Remove the user message if the request failed
      setMessages((prev) => prev.slice(0, -1))
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    sendMessage()
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const copyMessage = async (content: string, messageId: string) => {
    try {
      await navigator.clipboard.writeText(content)
      setCopiedMessageId(messageId)
      setTimeout(() => setCopiedMessageId(null), 2000)
    } catch (err) {
      console.error('Failed to copy message:', err)
    }
  }

  const exportChat = () => {
    const chatData = {
      user: user?.fullName,
      exportDate: new Date().toISOString(),
      messages: messages.map((msg) => ({
        sender: msg.sender,
        content: msg.content,
        timestamp: msg.timestamp,
      })),
    }

    const blob = new Blob([JSON.stringify(chatData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `chat-export-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const toggleVoiceRecording = async () => {
    if (!speechSupported) {
      setError(
        'Speech recognition is not supported in this browser. Please use Chrome, Edge, or Safari.'
      )
      return
    }

    if (!recognition) {
      setError('Speech recognition is not available.')
      return
    }

    if (isListening) {
      // Stop recording
      recognition.stop()
      setIsListening(false)
    } else {
      // Start recording
      try {
        // Request microphone permission first
        await navigator.mediaDevices.getUserMedia({ audio: true })

        setError('')
        recognition.start()
      } catch (err: any) {
        console.error('Microphone access error:', err)
        if (err.name === 'NotAllowedError') {
          setError(
            'Microphone access denied. Please allow microphone access in your browser settings.'
          )
        } else if (err.name === 'NotFoundError') {
          setError('No microphone found. Please connect a microphone and try again.')
        } else {
          setError('Unable to access microphone. Please check your browser settings.')
        }
      }
    }
  }

  return (
    <div className="flex flex-col h-screen bg-gray-50 dark:bg-gray-900">
      {isOnline && (
          <div></div>
        ) || ( <div className="text-red-500 text-opacity-90 px-2 fixed bg-white bg-opacity-15 w-full">You are offline, Please check your internet connection.</div> )
      }
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full flex items-center justify-center">
              <MessageCircle className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-gray-900 dark:text-white">AI Assistant</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Welcome back, {user?.fullName}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowTemplates(!showTemplates)}
              className="flex items-center space-x-2 px-3 py-2 text-sm dark:text-white bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors"
            >
              <Lightbulb className="h-4 w-4" />
              <span className="hidden sm:inline">Templates</span>
            </button>

            <button
              onClick={exportChat}
              disabled={messages.length === 0}
              className="flex items-center space-x-2 px-3 py-2 dark:text-white text-sm bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Download className="h-4 w-4" />
              <span className="hidden sm:inline">Export</span>
            </button>
          </div>
        </div>

        {/* Templates */}
        {showTemplates && (
          <div className="max-w-4xl mx-auto mt-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Quick Start Templates
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PROMPT_TEMPLATES.map((template, index) => (
                <button
                  key={index}
                  onClick={() => setSelectedTemplate(template)}
                  className="text-left p-3 text-sm bg-white dark:text-white dark:bg-gray-600 hover:bg-gray-100 dark:hover:bg-gray-500 rounded-lg transition-colors border border-gray-200 dark:border-gray-500"
                >
                  {template}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-4xl mx-auto space-y-6">
          {messages.length === 0 && (
            <div className="text-center py-12">
              <div className="h-16 w-16 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
                <Bot className="h-8 w-8 text-white" />
              </div>
              <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-2">
                Welcome to AI Assistant
              </h2>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Start a conversation by typing a message below or use one of our templates.
              </p>
              <button
                onClick={() => setShowTemplates(true)}
                className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white dark:text-white rounded-lg transition-colors"
              >
                <Lightbulb className="h-4 w-4" />
                <span>Browse Templates</span>
              </button>
            </div>
          )}

          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex items-start space-x-4 ${
                message.sender === 'user' ? 'flex-row-reverse space-x-reverse' : ''
              }`}
            >
              <div
                className={`flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center ${
                  message.sender === 'user'
                    ? 'bg-blue-600'
                    : 'bg-gradient-to-r from-purple-600 to-pink-600'
                }`}
              >
                {message.sender === 'user' ? (
                  <User className="h-5 w-5 text-white" />
                ) : (
                  <Bot className="h-5 w-5 text-white" />
                )}
              </div>

              <div
                className={`flex-1 max-w-3xl ${
                  message.sender === 'user' ? 'text-right' : 'text-left'
                }`}
              >
                <div
                  className={`inline-block p-4 rounded-2xl ${
                    message.sender === 'user'
                      ? 'bg-blue-600 text-white'
                      : 'bg-white dark:text-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700'
                  }`}
                >
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
                </div>

                <div className="flex items-center mt-2 space-x-2">
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    {message.timestamp?.toLocaleTimeString()}
                  </span>

                  {message.sender === 'bot' && (
                    <button
                      onClick={() => copyMessage(message.content, message.id!)}
                      className="text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
                    >
                      {copiedMessageId === message.id ? (
                        <Check className="h-3 w-3" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-start space-x-4">
              <div className="flex-shrink-0 h-10 w-10 rounded-full bg-gradient-to-r from-purple-600 to-pink-600 flex items-center justify-center">
                <Bot className="h-5 w-5 text-white" />
              </div>
              <div className="flex-1">
                <div className="inline-block p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl">
                  <div className="flex items-center space-x-2">
                    <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                    <span className="text-sm text-gray-500 dark:text-white">AI is thinking...</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center space-x-3 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <AlertCircle className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0" />
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input */}
      <div className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 px-4 py-4">
        <form onSubmit={handleSubmit} className="max-w-4xl mx-auto">
          <div className="flex items-end space-x-2">
            <div className="flex-1">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={
                  speechSupported
                    ? 'Type your message here or use voice input...'
                    : 'Type your message here...'
                }
                disabled={loading}
                className="w-full px-4 py-3 border scroll-m-1 border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none transition-colors"
                rows={1}
                style={{
                  minHeight: '48px',
                  maxHeight: '120px',
                  resize: 'none',
                }}
                onInput={(e) => {
                  const target = e.target as HTMLTextAreaElement
                  target.style.height = '48px'
                  target.style.height = Math.min(target.scrollHeight, 120) + 'px'
                }}
              />
            </div>
            <button
              type="button"
              onClick={toggleVoiceRecording}
              disabled={loading || !speechSupported}
              className={`flex-shrink-0 h-12 w-12 ${
                isListening
                  ? 'bg-red-600 hover:bg-red-700 animate-pulse'
                  : speechSupported
                  ? 'bg-gray-600 hover:bg-gray-700'
                  : 'bg-gray-400 cursor-not-allowed'
              } disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-xl transition-colors flex items-center justify-center`}
              title={
                !speechSupported
                  ? 'Speech recognition not supported'
                  : isListening
                  ? 'Stop recording (click or speak to finish)'
                  : 'Start voice input'
              }
            >
              {isListening ? <MicOff className="h-5 w-5" /> : <Mic className="h-5 w-5" />}
            </button>
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="flex-shrink-0 h-12 w-12 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-xl transition-colors flex items-center justify-center"
            >
              {loading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Send className="h-5 w-5" />
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default ChatPage
