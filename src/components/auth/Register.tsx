import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { Link, useNavigate } from 'react-router-dom';
import { Mail, Lock, User, Eye, EyeOff, TrendingUp, Phone, CheckCircle, Shield, Zap, Bot } from 'lucide-react';
import { authAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface RegisterForm {
  name: string;
  email: string;
  password?: string;
  confirmPassword: string;
  mobileNumber: string;
};

const Register: React.FC = () => {
  const [showPassword, setShowPassword] = React.useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showOtpForm, setShowOtpForm] = useState(false);
  const [showSuccessMessage, setShowSuccessMessage] = useState(false);
  const [otp, setOtp] = useState('');
  const [userIdentifier, setUserIdentifier] = useState('');
  const [canResendOtp, setCanResendOtp] = useState(false);
  const [resendTimer, setResendTimer] = useState(60);

  const { register, handleSubmit, watch, formState: { errors } } = useForm<RegisterForm>();
  const navigate = useNavigate();

  const password = watch('password');

  // Timer for resend OTP
  React.useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    
    if (showOtpForm && resendTimer > 0) {
      interval = setInterval(() => {
        setResendTimer((prev) => {
          if (prev <= 1) {
            setCanResendOtp(true);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [showOtpForm, resendTimer]);

  const onSubmit = async (data: RegisterForm) => {
    setIsLoading(true);
    try {
      if (!data.email && !data.mobileNumber) {
        toast.error('Please provide either an email or a mobile number.');
        setIsLoading(false);
        return;
      }

      const response = await authAPI.register(data);
      
      if (response.data.requiresOTP) {
        setShowOtpForm(true);
        setUserIdentifier(response.data.identifier);
        setResendTimer(60);
        setCanResendOtp(false);
        toast.success('OTP sent! Please check your email/SMS and enter the verification code.');
      } else {
        localStorage.setItem('authToken', response.data.token);
        toast.success('Registration successful!');
        navigate('/dashboard');
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpSubmit = async () => {
    if (!otp || otp.length !== 6) {
      toast.error('Please enter a valid 6-digit OTP');
      return;
    }

    setIsLoading(true);
    try {
      const response = await authAPI.verifyOtp({ identifier: userIdentifier, otp });
      
      if (response.data.accountCreated) {
        setShowOtpForm(false);
        setShowSuccessMessage(true);
        toast.success('Account created successfully! You can now login.');
        
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      } else {
        toast.success(response.data.message);
        navigate('/login');
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'OTP verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setIsLoading(true);
    try {
      await authAPI.resendOtp({ identifier: userIdentifier });
      toast.success('OTP resent successfully!');
      setResendTimer(60);
      setCanResendOtp(false);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to resend OTP');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 via-beige-100 to-sand-200 flex items-center justify-center px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Enhanced 3D Background Elements */}
      <div className="absolute inset-0 perspective-2000">
        <motion.div
          animate={{
            y: [0, -25, 0],
            rotateX: [0, 360, 0],
            rotateY: [0, 180, 0],
            scale: [1, 1.1, 1],
          }}
          transition={{
            duration: 16,
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
            y: [0, 30, 0],
            rotateY: [0, -360, 0],
            rotateZ: [0, 180, 0],
            scale: [1, 0.8, 1],
          }}
          transition={{
            duration: 20,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 4
          }}
          className="absolute bottom-20 right-20 w-32 h-32 bg-gradient-to-r from-bronze-500/15 to-amber-600/15 rounded-full backdrop-blur-sm"
          style={{ 
            transform: 'perspective(1000px) rotateX(-30deg) rotateY(60deg)',
            transformStyle: 'preserve-3d',
            boxShadow: '0 0 50px rgba(218, 143, 74, 0.4)'
          }}
        />

        {/* Floating Icons */}
        <motion.div
          animate={{
            y: [0, -15, 0],
            rotate: [0, 360],
          }}
          transition={{
            duration: 12,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          className="absolute top-1/3 right-1/4 w-16 h-16 bg-amber-500/10 rounded-full flex items-center justify-center backdrop-blur-sm"
        >
          <Bot className="w-8 h-8 text-amber-600/50" />
        </motion.div>

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
            scale: 1.01,
            rotateY: 1,
            rotateX: 1,
          }}
          className="bg-white/90 backdrop-blur-xl rounded-3xl p-8 border border-beige-200/50 shadow-3d hover:shadow-3d-hover transition-all duration-500"
          style={{ 
            transformStyle: 'preserve-3d',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 40px rgba(218, 143, 74, 0.1)'
          }}
        >
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
            <h2 className="text-4xl font-bold text-bronze-800 mb-3">Join AutoTraderHub</h2>
            <p className="text-bronze-600">Create your account and start trading smarter</p>
            
            {/* Feature Highlights */}
            <div className="flex justify-center space-x-6 mt-6">
              <div className="flex items-center space-x-2 text-bronze-600">
                <Shield className="w-4 h-4 text-amber-600" />
                <span className="text-sm">Secure</span>
              </div>
              <div className="flex items-center space-x-2 text-bronze-600">
                <Zap className="w-4 h-4 text-amber-600" />
                <span className="text-sm">Fast Setup</span>
              </div>
              <div className="flex items-center space-x-2 text-bronze-600">
                <Bot className="w-4 h-4 text-amber-600" />
                <span className="text-sm">AI-Powered</span>
              </div>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {!showOtpForm && !showSuccessMessage ? (
              <motion.form
                key="registration-form"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.4 }}
                onSubmit={handleSubmit(onSubmit)}
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Full Name
                  </label>
                  <div className="relative">
                    <User className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      {...register('name', {
                        required: 'Name is required',
                        minLength: {
                          value: 2,
                          message: 'Name must be at least 2 characters'
                        }
                      })}
                      type="text"
                      className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                      placeholder="Enter your full name"
                    />
                  </div>
                  {errors.name && (
                    <p className="mt-2 text-sm text-red-600">{errors.name.message}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Mobile Number
                  </label>
                  <div className="relative">
                    <Phone className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      {...register('mobileNumber', {
                        minLength: {
                          value: 10,
                          message: 'Please enter a valid mobile number'
                        }
                      })}
                      type="tel"
                      className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                      placeholder="Enter your mobile number"
                    />
                  </div>
                  {errors.mobileNumber && (
                    <p className="mt-2 text-sm text-red-600">{errors.mobileNumber.message}</p>
                  )}
                </div>

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
                      placeholder="Create a password"
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

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      {...register('confirmPassword', {
                        required: 'Please confirm your password',
                        validate: value => value === password || 'Passwords do not match'
                      })}
                      type={showConfirmPassword ? 'text' : 'password'}
                      className="w-full pl-12 pr-14 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                      placeholder="Confirm your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-4 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                    >
                      {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                  {errors.confirmPassword && (
                    <p className="mt-2 text-sm text-red-600">{errors.confirmPassword.message}</p>
                  )}
                </div>

                <div className="flex items-start">
                  <input
                    type="checkbox"
                    className="w-4 h-4 text-amber-600 bg-cream-50 border-beige-200 rounded focus:ring-amber-500 mt-1"
                    required
                  />
                  <label className="ml-2 text-sm text-bronze-600">
                    I agree to the
                    <Link to="/terms" className="text-amber-600 hover:text-amber-500 transition-colors font-medium">
                      {' '}Terms of Service{' '}
                    </Link>
                    and
                    <Link to="/privacy" className="text-amber-600 hover:text-amber-500 transition-colors font-medium">
                      {' '}Privacy Policy
                    </Link>
                  </label>
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
                      <span>Creating Account...</span>
                    </div>
                  ) : (
                    'Create Account'
                  )}
                </motion.button>
              </motion.form>
            ) : showSuccessMessage ? (
              <motion.div
                key="success-message"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.4 }}
                className="text-center space-y-6"
              >
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
                  className="w-20 h-20 bg-gradient-to-r from-green-500 to-green-600 rounded-full flex items-center justify-center mx-auto shadow-3d"
                >
                  <CheckCircle className="w-10 h-10 text-white" />
                </motion.div>
                
                <div>
                  <h3 className="text-2xl font-bold text-bronze-800 mb-2">Account Created Successfully!</h3>
                  <p className="text-bronze-600 mb-4">
                    Your AutoTraderHub account has been created. You can now login with your credentials.
                  </p>
                  <p className="text-amber-600 text-sm">
                    Redirecting to login page in 3 seconds...
                  </p>
                </div>

                <motion.button
                  onClick={() => navigate('/login')}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-8 py-3 rounded-xl font-medium hover:shadow-3d transition-all shadow-3d"
                >
                  Go to Login
                </motion.button>
              </motion.div>
            ) : (
              <motion.div
                key="otp-verification-form"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.4 }}
                className="space-y-6"
              >
                <div className="text-center mb-6">
                  <h3 className="text-2xl font-bold text-bronze-800">Verify Your Account</h3>
                  <p className="text-bronze-600 mt-2">
                    We've sent a 6-digit verification code to
                  </p>
                  <p className="text-amber-600 font-medium">{userIdentifier}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Verification Code
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      type="text"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm text-center text-lg tracking-widest shadow-inner-3d"
                      placeholder="000000"
                      maxLength={6}
                    />
                  </div>
                </div>

                <motion.button
                  whileHover={{ scale: 1.02, rotateX: 5 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={handleOtpSubmit}
                  disabled={isLoading || otp.length !== 6}
                  className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-4 rounded-xl font-bold text-lg hover:shadow-3d-hover transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-3d"
                  style={{
                    boxShadow: '0 10px 25px rgba(218, 143, 74, 0.3)'
                  }}
                >
                  {isLoading ? (
                    <div className="flex items-center justify-center space-x-2">
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Verifying...</span>
                    </div>
                  ) : (
                    'Verify & Create Account'
                  )}
                </motion.button>

                <div className="text-center">
                  {canResendOtp ? (
                    <motion.button
                      type="button"
                      onClick={handleResendOtp}
                      disabled={isLoading}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      className="text-amber-600 hover:text-amber-500 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      {isLoading ? 'Sending...' : 'Resend OTP'}
                    </motion.button>
                  ) : (
                    <p className="text-bronze-600 text-sm">
                      Resend OTP in {resendTimer} seconds
                    </p>
                  )}
                </div>

                <motion.button
                  type="button"
                  onClick={() => {
                    setShowOtpForm(false);
                    setOtp('');
                    setUserIdentifier('');
                  }}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium hover:bg-beige-200 transition-all border border-beige-200 shadow-inner-3d"
                >
                  Back to Registration
                </motion.button>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="mt-8 text-center">
            <p className="text-bronze-600">
              Already have an account?{' '}
              <Link
                to="/login"
                className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
              >
                Sign in here
              </Link>
            </p>
          </div>

          {/* Security Badge */}
          <div className="mt-6 pt-6 border-t border-beige-200">
            <div className="flex items-center justify-center space-x-2 text-bronze-500">
              <Shield className="w-4 h-4" />
              <span className="text-xs">Your data is protected with enterprise-grade security</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default Register;