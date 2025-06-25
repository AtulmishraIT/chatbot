"use client"
import {useEffect, useState} from "react"
import { Link } from "react-router-dom"
import { useAuth } from "../contexts/AuthContext"
import { MessageCircle, Shield, Zap, Brain, ArrowRight, Star } from "lucide-react"

const HomePage = () => {
  const { isAuthenticated } = useAuth()
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const handleOnline = () => {
      if(!navigator.onLine){
        setIsOnline(false);
      }
      else
        setIsOnline(true);
    }
    handleOnline();
  })
  

  const features = [
    {
      icon: Brain,
      title: "Advanced AI",
      description: "Powered by state-of-the-art language models for intelligent conversations",
    },
    {
      icon: Shield,
      title: "Secure & Private",
      description: "Your conversations are encrypted and stored securely with JWT authentication",
    },
    {
      icon: Zap,
      title: "Lightning Fast",
      description: "Real-time responses with optimized performance and minimal latency",
    },
  ]

  const testimonials = [
    {
      name: "Sarah Johnson",
      role: "Product Manager",
      content: "This AI chatbot has revolutionized how I brainstorm ideas and solve problems.",
      rating: 5,
    },
    {
      name: "Mike Chen",
      role: "Developer",
      content: "The interface is clean and the responses are incredibly helpful for coding questions.",
      rating: 5,
    },
    {
      name: "Emily Davis",
      role: "Writer",
      content: "Perfect for creative writing assistance and overcoming writer's block.",
      rating: 5,
    },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      {isOnline && (
          <div></div>
        ) || ( <div className="text-red-500 text-opacity-90 px-2 fixed bg-white bg-opacity-15 w-full">You are offline, Please check your internet connection.</div> )
      }
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
          <div className="text-center">
            <div className="mx-auto h-20 w-20 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full flex items-center justify-center mb-8">
              <MessageCircle className="h-10 w-10 text-white" />
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gray-900 dark:text-white mb-6">
              Your Intelligent
              <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                {" "}
                AI Assistant
              </span>
            </h1>

            <p className="text-xl text-gray-600 dark:text-gray-300 mb-8 max-w-3xl mx-auto leading-relaxed">
              Experience the future of conversation with our advanced AI chatbot. Get instant answers, creative
              assistance, and intelligent support for all your questions.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              {isAuthenticated ? (
                <Link
                  to="/chat"
                  className="inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-xl text-white bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-1"
                >
                  Continue Chatting
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Link>
              ) : (
                <>
                  <Link
                    to="/register"
                    className="inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-xl text-white bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-1"
                  >
                    Get Started Free
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Link>

                  <Link
                    to="/login"
                    className="inline-flex items-center px-8 py-4 border border-gray-300 dark:border-gray-600 text-lg font-medium rounded-xl text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-all duration-200 shadow-lg hover:shadow-xl"
                  >
                    Sign In
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="py-24 bg-white dark:bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Why Choose Our AI Chatbot?
            </h2>
            <p className="text-xl text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              Built with cutting-edge technology to provide you with the best conversational AI experience.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div
                  key={index}
                  className="text-center p-8 bg-gray-50 dark:bg-gray-700 rounded-2xl hover:shadow-lg transition-all duration-200 transform hover:-translate-y-2"
                >
                  <div className="mx-auto h-16 w-16 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full flex items-center justify-center mb-6">
                    <Icon className="h-8 w-8 text-white" />
                  </div>
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">{feature.title}</h3>
                  <p className="text-gray-600 dark:text-gray-300 leading-relaxed">{feature.description}</p>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Demo Section */}
      <div className="py-24 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-900 dark:to-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-4">See It In Action</h2>
            <p className="text-xl text-gray-600 dark:text-gray-300">Here's what a conversation looks like</p>
          </div>

          <div className="max-w-4xl mx-auto bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
            <div className="bg-gray-50 dark:bg-gray-700 px-6 py-4 border-b border-gray-200 dark:border-gray-600">
              <div className="flex items-center space-x-3">
                <div className="flex space-x-2">
                  <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                  <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                </div>
                <span className="text-sm font-medium text-gray-600 dark:text-gray-300">AI Chat Assistant</span>
              </div>
            </div>

            <div className="p-6 space-y-4 h-96 overflow-y-auto">
              <div className="flex justify-end">
                <div className="bg-blue-600 text-white rounded-2xl px-4 py-3 max-w-xs">
                  <p className="text-sm">Hello! Can you help me write a creative story about space exploration?</p>
                </div>
              </div>

              <div className="flex justify-start">
                <div className="bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-2xl px-4 py-3 max-w-md">
                  <p className="text-sm">
                    I'd be happy to help you write a creative story about space exploration! Here's a compelling
                    opening:
                  </p>
                  <p className="text-sm mt-2 italic">
                    "Captain Maya Chen gazed through the viewport at the swirling nebula ahead, its colors shifting like
                    a cosmic aurora. After three years of deep space travel, her crew was about to make first contact
                    with an alien civilization..."
                  </p>
                </div>
              </div>

              <div className="flex justify-end">
                <div className="bg-blue-600 text-white rounded-2xl px-4 py-3 max-w-xs">
                  <p className="text-sm">That's amazing! Can you continue with what happens next?</p>
                </div>
              </div>

              <div className="flex justify-start">
                <div className="bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-2xl px-4 py-3 max-w-md">
                  <p className="text-sm">Let's continue the adventure...</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Testimonials Section */}
      <div className="py-24 bg-white dark:bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-4">What Our Users Say</h2>
            <p className="text-xl text-gray-600 dark:text-gray-300">
              Join thousands of satisfied users who love our AI assistant
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <div
                key={index}
                className="bg-gray-50 dark:bg-gray-700 p-8 rounded-2xl hover:shadow-lg transition-all duration-200"
              >
                <div className="flex items-center mb-4">
                  {[...Array(testimonial.rating)].map((_, i) => (
                    <Star key={i} className="h-5 w-5 text-yellow-400 fill-current" />
                  ))}
                </div>
                <p className="text-gray-600 dark:text-gray-300 mb-6 italic">"{testimonial.content}"</p>
                <div>
                  <p className="font-semibold text-gray-900 dark:text-white">{testimonial.name}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{testimonial.role}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="py-24 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">Ready to Start Chatting?</h2>
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            Join our community and experience the power of AI conversation today.
          </p>

          {!isAuthenticated && (
            <Link
              to="/register"
              className="inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-xl text-blue-600 bg-white hover:bg-gray-50 transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-1"
            >
              Get Started Now
              <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}

export default HomePage
