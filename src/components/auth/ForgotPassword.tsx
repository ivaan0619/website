import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { Mail, Lock, TrendingUp, Shield, Clock, CheckCircle, ArrowLeft } from 'lucide-react';
import toast, { Toaster } from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../../services/api';

type FormStep = 1 | 2 | 3;

interface ForgotForm {
  email?: string;
  otp?: string;
  password?: string;
  confirmPassword?: string;
}

export default function ForgotPassword() {
  const [step, setStep] = useState<FormStep>(1);
  const [identifier, setIdentifier] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [canResendOtp, setCanResendOtp] = useState(false);
  const [resendTimer, setResendTimer] = useState(60);
  const [timerActive, setTimerActive] = useState(false);

  // Start timer function
  const startResendTimer = () => {
    setCanResendOtp(false);
    setResendTimer(60);
    setTimerActive(true);
  };

  // Handle timer effect
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    
    if (timerActive && resendTimer > 0) {
      interval = setInterval(() => {
        setResendTimer((prev) => {
          if (prev <= 1) {
            setTimerActive(false);
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
  }, [timerActive, resendTimer]);

  // Handle resend OTP
  const handleResendOtp = async () => {
    if (!identifier) {
      toast.error('No identifier found. Please restart the process.');
      return;
    }

    try {
      setIsLoading(true);
      await authAPI.forgotPassword({ identifier });
      toast.success('OTP resent successfully');
      startResendTimer();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to resend OTP');
    } finally {
      setIsLoading(false);
    }
  };

  const { register, handleSubmit, watch, reset, formState: { errors } } = useForm<ForgotForm>();
  const navigate = useNavigate();

  const password = watch('password');

  const handleNext = async (data: ForgotForm) => {
    setIsLoading(true);
    try {
      if (step === 1) {
        const id = data.email || '';
        if (!id) {
          toast.error('Please enter your email');
          setIsLoading(false);
          return;
        }
        setIdentifier(id);
        await authAPI.forgotPassword({ identifier: id });
        toast.success('OTP sent successfully');
        setStep(2);
        startResendTimer();
      } else if (step === 2) {
        if (!data.otp) {
          toast.error('Please enter the OTP');
          setIsLoading(false);
          return;
        }
        const verifyResponse = await authAPI.verifyOtpForReset({ identifier, otp: data.otp });
        if (verifyResponse.data.message === 'OTP verified successfully') {
          setResetToken(verifyResponse.data.resetToken);
          toast.success('OTP verified successfully');
          setStep(3);
        }
      } else {
        if (!data.password || !data.confirmPassword) {
          toast.error('Please enter and confirm your new password');
          setIsLoading(false);
          return;
        }
        if (data.password !== data.confirmPassword) {
          toast.error('Passwords do not match');
          setIsLoading(false);
          return;
        }
        
        if (!resetToken || !data.password) {
          console.error('Missing required fields:', { resetToken, password: data.password });
          toast.error('Missing required fields for password reset');
          return;
        }

        try {
          console.log('Attempting password reset with reset token');

          const response = await authAPI.resetPassword({
            resetToken,
            newPassword: data.password
          });

          console.log('Reset password response:', response);

          if (response.data?.message === 'Password reset successfully') {
            toast.success('Password reset successfully');
            reset();
            navigate('/login');
          } else {
            throw new Error('Unexpected response from server');
          }
        } catch (error: any) {
          console.error('Reset password error:', error);
          console.error('Error response data:', error.response?.data);
          const errorMessage = error.response?.data?.error || error.message || 'Failed to reset password';
          toast.error(errorMessage);
          throw error;
        }
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 via-beige-100 to-sand-200 flex items-center justify-center px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      <Toaster position="top-right" />
      
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
            duration: 18,
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
            duration: 22,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 5
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
            duration: 14,
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
            <h2 className="text-4xl font-bold text-bronze-800 mb-3">Reset Password</h2>
            <p className="text-bronze-600">Secure password recovery for your AutoTraderHub account</p>
            
            {/* Step indicator */}
            <div className="flex justify-center mt-6 space-x-2">
              {[1, 2, 3].map((stepNum) => (
                <div
                  key={stepNum}
                  className={`w-3 h-3 rounded-full transition-all duration-300 ${
                    stepNum === step
                      ? 'bg-amber-500 scale-125 shadow-3d'
                      : stepNum < step
                      ? 'bg-amber-600'
                      : 'bg-beige-300'
                  }`}
                />
              ))}
            </div>
            
            {/* Step Labels */}
            <div className="flex justify-center mt-2 space-x-8 text-xs text-bronze-500">
              <span className={step >= 1 ? 'text-amber-600 font-medium' : ''}>Email</span>
              <span className={step >= 2 ? 'text-amber-600 font-medium' : ''}>Verify</span>
              <span className={step >= 3 ? 'text-amber-600 font-medium' : ''}>Reset</span>
            </div>
          </div>

          <form onSubmit={handleSubmit(handleNext)} className="space-y-6">
            {step === 1 && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.4 }}
              >
                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Email Address
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      type="email"
                      {...register('email', {
                        required: 'Email is required',
                        pattern: {
                          value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                          message: 'Invalid email address'
                        }
                      })}
                      className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                      placeholder="Enter your email"
                    />
                  </div>
                  {errors.email && (
                    <p className="mt-2 text-sm text-red-600">{errors.email.message}</p>
                  )}
                </div>
                
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mt-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Shield className="w-4 h-4 text-amber-600" />
                    <span className="text-amber-700 text-sm font-medium">Security Notice</span>
                  </div>
                  <p className="text-amber-600 text-xs">
                    We'll send a secure verification code to your email address to verify your identity.
                  </p>
                </div>
              </motion.div>
            )}

            {step === 2 && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.4 }}
              >
                <div className="text-center mb-6">
                  <p className="text-sm text-bronze-600 mb-2">
                    Enter the verification code sent to
                  </p>
                  <p className="font-medium text-bronze-800 text-lg">
                    {identifier}
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Verification Code
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                    <input
                      type="text"
                      {...register('otp', {
                        required: 'OTP is required',
                        pattern: {
                          value: /^\d{6}$/,
                          message: 'OTP must be 6 digits'
                        }
                      })}
                      className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm text-center text-lg tracking-widest shadow-inner-3d"
                      placeholder="000000"
                      maxLength={6}
                    />
                  </div>
                  {errors.otp && (
                    <p className="mt-2 text-sm text-red-600">{errors.otp.message}</p>
                  )}
                </div>
                <div className="text-center mt-4">
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
                    <div className="flex items-center justify-center space-x-2 text-bronze-600 text-sm">
                      <Clock className="w-4 h-4" />
                      <span>Resend OTP in {resendTimer} seconds</span>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {step === 3 && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.4 }}
              >
                <div className="text-center mb-6">
                  <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <CheckCircle className="w-8 h-8 text-green-600" />
                  </div>
                  <p className="text-sm text-bronze-600 mb-2">
                    Identity verified! Set a new password for
                  </p>
                  <p className="font-medium text-bronze-800 text-lg">
                    {identifier}
                  </p>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-bronze-700 mb-2">
                      New Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                      <input
                        type="password"
                        {...register('password', { 
                          required: 'Password is required',
                          minLength: {
                            value: 6,
                            message: 'Password must be at least 6 characters'
                          }
                        })}
                        className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                        placeholder="Enter new password"
                      />
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
                        type="password"
                        {...register('confirmPassword', {
                          required: 'Please confirm your password',
                          validate: value => value === password || 'Passwords do not match',
                        })}
                        className="w-full pl-12 pr-4 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                        placeholder="Confirm new password"
                      />
                    </div>
                    {errors.confirmPassword && (
                      <p className="mt-2 text-sm text-red-600">{errors.confirmPassword.message}</p>
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            <motion.button
              type="submit"
              disabled={isLoading}
              whileHover={{ scale: 1.02, rotateX: 5 }}
              whileTap={{ scale: 0.98 }}
              className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-4 rounded-xl font-bold text-lg hover:shadow-3d-hover transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-3d"
              style={{
                boxShadow: '0 10px 25px rgba(218, 143, 74, 0.3)',
              }}
            >
              {isLoading ? (
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Processing...</span>
                </div>
              ) : (
                step === 1 ? 'Send Verification Code' :
                step === 2 ? 'Verify Code' :
                'Reset Password'
              )}
            </motion.button>

            {step > 1 && (
              <motion.button
                type="button"
                onClick={() => {
                  setStep((step - 1) as FormStep);
                  reset();
                }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium hover:bg-beige-200 transition-all border border-beige-200 shadow-inner-3d flex items-center justify-center space-x-2"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back</span>
              </motion.button>
            )}
          </form>

          {/* Security Footer */}
          <div className="mt-8 pt-6 border-t border-beige-200">
            <div className="flex items-center justify-center space-x-2 text-bronze-500">
              <Shield className="w-4 h-4" />
              <span className="text-xs">Secure password reset with end-to-end encryption</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
}