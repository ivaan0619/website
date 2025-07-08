import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Lock, TrendingUp, Shield, Clock, ArrowLeft, RefreshCw } from 'lucide-react';
import { authAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface VerifyOtpForm {
  otp: string;
}

interface LocationState {
  identifier?: string;
}

const VerifyOtpResetPassword: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [canResendOtp, setCanResendOtp] = useState(false);
  const [resendTimer, setResendTimer] = useState(60);
  const navigate = useNavigate();
  const location = useLocation();
  const { identifier } = location.state as LocationState || {};

  const { register, handleSubmit, formState: { errors } } = useForm<VerifyOtpForm>();

  // Timer for resend OTP
  React.useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    
    if (resendTimer > 0) {
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
  }, [resendTimer]);

  const onSubmit = async (data: VerifyOtpForm) => {
    if (!identifier) {
      toast.error("Identifier not found. Please go back to the forgot password page.");
      return;
    }

    setIsLoading(true);
    try {
      const response = await authAPI.verifyOtp({ identifier, otp: data.otp });
      toast.success(response.data.message);
      navigate('/reset-password', { state: { identifier } });
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'OTP verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOtp = async () => {
    if (!identifier) {
      toast.error('No identifier found. Please restart the process.');
      return;
    }

    try {
      setIsLoading(true);
      await authAPI.forgotPassword({ identifier });
      toast.success('OTP resent successfully');
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
            y: [0, -20, 0],
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
            y: [0, 25, 0],
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

        {/* Floating Security Icons */}
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
          <Shield className="w-8 h-8 text-amber-600/50" />
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
            <h2 className="text-4xl font-bold text-bronze-800 mb-3">Verify OTP</h2>
            <p className="text-bronze-600">
              Enter the verification code to continue with password reset
            </p>
            
            {identifier && (
              <div className="mt-6 p-4 bg-amber-50 border border-amber-200 rounded-xl">
                <p className="text-sm text-amber-700 mb-1">Verification code sent to:</p>
                <p className="font-medium text-amber-800">{identifier}</p>
              </div>
            )}
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-bronze-700 mb-2">
                Verification Code
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                <input
                  {...register('otp', {
                    required: 'OTP is required',
                    minLength: {
                      value: 6,
                      message: 'OTP must be 6 digits'
                    },
                    maxLength: {
                      value: 6,
                      message: 'OTP must be 6 digits'
                    }
                  })}
                  type="text"
                  className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm text-center text-lg tracking-widest shadow-inner-3d"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
              {errors.otp && (
                <p className="mt-2 text-sm text-red-600">{errors.otp.message}</p>
              )}
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
                  <span>Verifying...</span>
                </div>
              ) : (
                'Verify OTP'
              )}
            </motion.button>

            {/* Resend OTP Section */}
            <div className="text-center">
              {canResendOtp ? (
                <motion.button
                  type="button"
                  onClick={handleResendOtp}
                  disabled={isLoading}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="flex items-center justify-center space-x-2 text-amber-600 hover:text-amber-500 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed mx-auto"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>{isLoading ? 'Sending...' : 'Resend OTP'}</span>
                </motion.button>
              ) : (
                <div className="flex items-center justify-center space-x-2 text-bronze-600 text-sm">
                  <Clock className="w-4 h-4" />
                  <span>Resend OTP in {resendTimer} seconds</span>
                </div>
              )}
            </div>

            {/* Back Button */}
            <motion.button
              type="button"
              onClick={() => navigate('/forgot-password')}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium hover:bg-beige-200 transition-all border border-beige-200 shadow-inner-3d flex items-center justify-center space-x-2"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Forgot Password</span>
            </motion.button>
          </form>

          <div className="mt-8 text-center">
            <p className="text-bronze-600">
              Remember your password?{' '}
              <Link
                to="/login"
                className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
              >
                Sign in here
              </Link>
            </p>
          </div>

          {/* Security Footer */}
          <div className="mt-6 pt-6 border-t border-beige-200">
            <div className="flex items-center justify-center space-x-2 text-bronze-500">
              <Shield className="w-4 h-4" />
              <span className="text-xs">Secure verification with time-limited codes</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default VerifyOtpResetPassword;