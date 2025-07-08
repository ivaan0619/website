import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Lock, Eye, EyeOff, TrendingUp, Shield, CheckCircle, ArrowLeft } from 'lucide-react';
import { authAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface ResetPasswordForm {
  newPassword: string;
  confirmNewPassword: string;
}

const ResetPassword: React.FC = () => {
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmNewPassword, setShowConfirmNewPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const { register, handleSubmit, watch, formState: { errors } } = useForm<ResetPasswordForm>();
  const navigate = useNavigate();
  const location = useLocation();

  const { identifier } = location.state || {};
  const newPassword = watch('newPassword');

  const onSubmit = async (data: ResetPasswordForm) => {
    if (!identifier) {
      toast.error('Identifier not found. Please restart the password reset process.');
      navigate('/forgot-password');
      return;
    }

    setIsLoading(true);
    try {
      const response = await authAPI.resetPassword({
        identifier,
        newPassword: data.newPassword,
      });
      toast.success(response.data.message);
      navigate('/login');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Password reset failed');
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
            <p className="text-bronze-600">Set a new secure password for your account</p>
            
            {identifier && (
              <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-xl">
                <div className="flex items-center justify-center space-x-2 mb-2">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                  <span className="text-sm text-green-700 font-medium">Identity Verified</span>
                </div>
                <p className="text-sm text-green-600">
                  Resetting password for: <span className="font-semibold">{identifier}</span>
                </p>
              </div>
            )}
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-bronze-700 mb-2">
                New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                <input
                  {...register('newPassword', {
                    required: 'New password is required',
                    minLength: {
                      value: 6,
                      message: 'Password must be at least 6 characters'
                    }
                  })}
                  type={showNewPassword ? 'text' : 'password'}
                  className="w-full pl-12 pr-14 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                  placeholder="Enter new password"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              {errors.newPassword && (
                <p className="mt-2 text-sm text-red-600">{errors.newPassword.message}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-bronze-700 mb-2">
                Confirm New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
                <input
                  {...register('confirmNewPassword', {
                    required: 'Please confirm your new password',
                    validate: value => value === newPassword || 'Passwords do not match'
                  })}
                  type={showConfirmNewPassword ? 'text' : 'password'}
                  className="w-full pl-12 pr-14 py-4 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent transition-all backdrop-blur-sm shadow-inner-3d"
                  placeholder="Confirm new password"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmNewPassword(!showConfirmNewPassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                >
                  {showConfirmNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              {errors.confirmNewPassword && (
                <p className="mt-2 text-sm text-red-600">{errors.confirmNewPassword.message}</p>
              )}
            </div>

            {/* Password Strength Indicator */}
            {newPassword && (
              <div className="space-y-2">
                <div className="text-sm text-bronze-700">Password Strength:</div>
                <div className="flex space-x-1">
                  {[1, 2, 3, 4].map((level) => (
                    <div
                      key={level}
                      className={`h-2 flex-1 rounded-full transition-colors ${
                        newPassword.length >= level * 2
                          ? level <= 2
                            ? 'bg-red-400'
                            : level === 3
                            ? 'bg-amber-400'
                            : 'bg-green-400'
                          : 'bg-beige-200'
                      }`}
                    />
                  ))}
                </div>
                <div className="text-xs text-bronze-500">
                  {newPassword.length < 6 && 'Too short'}
                  {newPassword.length >= 6 && newPassword.length < 8 && 'Fair'}
                  {newPassword.length >= 8 && newPassword.length < 12 && 'Good'}
                  {newPassword.length >= 12 && 'Strong'}
                </div>
              </div>
            )}

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
                  <span>Resetting Password...</span>
                </div>
              ) : (
                'Reset Password'
              )}
            </motion.button>

            {/* Back Button */}
            <motion.button
              type="button"
              onClick={() => navigate('/forgot-password')}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium hover:bg-beige-200 transition-all border border-beige-200 shadow-inner-3d flex items-center justify-center space-x-2"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Verification</span>
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
              <span className="text-xs">Password encrypted with AES-256 security</span>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default ResetPassword;