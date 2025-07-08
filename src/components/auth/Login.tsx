import React from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { Link, useNavigate } from 'react-router-dom';
import { Mail, Lock, Eye, EyeOff, TrendingUp, AlertCircle, Shield, Zap } from 'lucide-react';
import { authAPI } from '../../services/api';
import toast, { Toaster } from 'react-hot-toast';

interface LoginForm {
  email: string;
  password: string;
}

const Login: React.FC = () => {
  const [showPassword, setShowPassword] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(false);
  const [loginError, setLoginError] = React.useState<string>('');
  const { register, handleSubmit, formState: { errors } } = useForm<LoginForm>();
  const navigate = useNavigate();

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);
    setLoginError('');
    
    try {
      const response = await authAPI.login(data);
      localStorage.setItem('authToken', response.data.access_token);
      toast.success('Login successful!');
      navigate('/dashboard');
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Login failed';
      const errorDetails = error.response?.data?.message || '';
      
      setLoginError(errorMessage);
      
      // Show specific error messages
      if (error.response?.status === 404) {
        toast.error('Account not found. Please check your email or create a new account.');
      } else if (error.response?.status === 401) {
        toast.error('Invalid password. Please try again.');
      } else {
        toast.error(errorMessage);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 via-beige-100 to-sand-200 flex items-center justify-center px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      <Toaster position="top-right" />
      
      {/* Enhanced 3D Background Elements */}
      <div className="absolute inset-0 perspective-2000">
        {/* Floating 3D Geometric Shapes */}
        <motion.div
          animate={{
            y: [0, -30, 0],
            rotateX: [0, 360, 0],
            rotateY: [0, 180, 0],
            scale: [1, 1.1, 1],
          }}
          transition={{
            duration: 15,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          className="absolute top-20 left-20 w-24 h-24 bg-gradient-to-r from-amber-500/20 to-bronze-600/20 rounded-2xl backdrop-blur-sm"
          style={{ 
            transform: 'perspective(1000px) rotateX(45deg) rotateY(45deg)',
            transformStyle: 'preserve-3d',
            boxShadow: '0 0 40px rgba(218, 143, 74, 0.3)'
          }}
        />
        
        <motion.div
          animate={{
            y: [0, 25, 0],
            rotateX: [0, -180, 0],
            rotateZ: [0, 90, 0],
            scale: [1, 0.8, 1],
          }}
          transition={{
            duration: 18,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 3
          }}
          className="absolute top-40 right-32 w-20 h-20 bg-gradient-to-r from-bronze-500/25 to-amber-600/25 rounded-full backdrop-blur-sm"
          style={{ 
            transform: 'perspective(1000px) rotateX(-30deg) rotateY(60deg)',
            transformStyle: 'preserve-3d',
            boxShadow: '0 0 30px rgba(218, 143, 74, 0.4)'
          }}
        />

        <motion.div
          animate={{
            y: [0, -20, 0],
            rotateY: [0, 360, 0],
            scale: [1, 1.2, 1],
          }}
          transition={{
            duration: 12,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 6
          }}
          className="absolute bottom-32 left-1/4 w-28 h-28 bg-gradient-to-r from-amber-400/20 to-bronze-500/20 backdrop-blur-sm"
          style={{ 
            transform: 'perspective(1000px) rotateX(60deg) rotateZ(30deg)',
            transformStyle: 'preserve-3d',
            borderRadius: '30%',
            boxShadow: '0 0 50px rgba(218, 143, 74, 0.5)'
          }}
        />

        {/* Animated Grid Background */}
        <div className="absolute inset-0 opacity-5">
          <div 
            className="w-full h-full"
            style={{
              backgroundImage: `
                linear-gradient(rgba(218, 143, 74, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(218, 143, 74, 0.1) 1px, transparent 1px)
              `,
              backgroundSize: '60px 60px',
              transform: 'perspective(1000px) rotateX(60deg)',
              transformOrigin: 'center bottom'
            }}
          />
        </div>

        {/* Glowing Orbs */}
        <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-amber-500/10 rounded-full blur-3xl animate-pulse-glow"></div>
        <div className="absolute bottom-1/3 right-1/3 w-80 h-80 bg-bronze-500/15 rounded-full blur-3xl animate-pulse-glow" style={{ animationDelay: '2s' }}></div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, rotateX: -15 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={{ duration: 0.8 }}
        className="relative z-10 max-w-md w-full space-y-8"
        style={{ perspective: '1000px' }}
      >
        <motion.div
          whileHover={{ 
            scale: 1.02,
            rotateY: 2,
            rotateX: 2,
          }}
          className="bg-white/90 backdrop-blur-xl rounded-3xl p-8 border border-beige-200/50 shadow-3d hover:shadow-3d-hover transition-all duration-500"
          style={{ 
            transformStyle: 'preserve-3d',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 40px rgba(218, 143, 74, 0.1)'
          }}
        >
          {/* Header Section */}
          <div className="text-center mb-8">
            <motion.div 
              className="flex justify-center mb-6"
              whileHover={{ rotateY: 180 }}
              transition={{ duration: 0.6 }}
            >
              <div className="w-20 h-20 bg-gradient-to-r from-amber-500 to-bronze-600 rounded-3xl flex items-center justify-center shadow-3d">
                <TrendingUp className="w-10 h-10 text-white" />
              </div>
            </motion.div>
            <h2 className="text-4xl font-bold text-bronze-800 mb-3">Welcome Back</h2>
            <p className="text-bronze-600">Sign in to your AutoTraderHub account</p>
            
            {/* Feature Highlights */}
            <div className="flex justify-center space-x-6 mt-6">
              <div className="flex items-center space-x-2 text-bronze-600">
                <Shield className="w-4 h-4 text-amber-600" />
                <span className="text-sm">Secure</span>
              </div>
              <div className="flex items-center space-x-2 text-bronze-600">
                <Zap className="w-4 h-4 text-amber-600" />
                <span className="text-sm">Fast</span>
              </div>
              <div className="flex items-center space-x-2 text-bronze-600">
                <TrendingUp className="w-4 h-4 text-amber-600" />
                <span className="text-sm">Automated</span>
              </div>
            </div>
          </div>

          {/* Error Message Display */}
          {loginError && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl flex items-center space-x-3"
            >
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
              <div>
                <p className="text-red-700 font-medium">{loginError}</p>
                {loginError === 'Account not available' && (
                  <p className="text-red-600 text-sm mt-1">
                    Don't have an account? <Link to="/register" className="text-red-700 hover:text-red-600 underline font-medium">Create one here</Link>
                  </p>
                )}
              </div>
            </motion.div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-bronze-700 mb-2">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                <input
                  {...register('email', { 
                    required: 'Email is required',
                    pattern: {
                      value: /^\S+@\S+$/i,
                      message: 'Please enter a valid email'
                    }
                  })}
                  type="email"
                  className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                  placeholder="Enter your email"
                />
              </div>
              {errors.email && (
                <p className="mt-2 text-sm text-red-600">{errors.email.message}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-bronze-700 mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                <input
                  {...register('password', { 
                    required: 'Password is required',
                    minLength: {
                      value: 6,
                      message: 'Password must be at least 6 characters'
                    }
                  })}
                  type={showPassword ? 'text' : 'password'}
                  className="w-full pl-12 pr-14 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              {errors.password && (
                <p className="mt-2 text-sm text-red-600">{errors.password.message}</p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  className="w-4 h-4 text-amber-600 bg-cream-50 border-beige-200 rounded focus:ring-amber-500"
                />
                <span className="ml-2 text-sm text-bronze-600">Remember me</span>
              </label>
              <Link
                to="/forgot-password"
                className="text-sm text-amber-600 hover:text-amber-500 transition-colors font-medium"
              >
                Forgot password?
              </Link>
            </div>

            <motion.button
              whileHover={{ scale: 1.02, rotateX: 5 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-4 rounded-xl font-bold text-lg hover:shadow-3d-hover transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-3d"
              style={{ 
                boxShadow: '0 10px 25px rgba(218, 143, 74, 0.3)'
              }}
            >
              {isLoading ? (
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Signing In...</span>
                </div>
              ) : (
                'Sign In'
              )}
            </motion.button>
          </form>

          <div className="mt-8 text-center">
            <p className="text-bronze-600">
              Don't have an account?{' '}
              <Link
                to="/register"
                className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
              >
                Sign up here
              </Link>
            </p>
          </div>

          {/* Security Badge */}
          <div className="mt-6 pt-6 border-t border-beige-200">
            <div className="flex items-center justify-center space-x-2 text-bronze-500">
              <Shield className="w-4 h-4" />
              <span className="text-xs">256-bit SSL encrypted</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default Login;