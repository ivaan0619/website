import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Crown, Lock, ArrowRight } from 'lucide-react';
import { subscriptionAPI } from '../../services/api';
import { useNavigate } from 'react-router-dom';

interface SubscriptionGuardProps {
  children: React.ReactNode;
  feature?: string;
}

interface Subscription {
  id: string;
  planId: string;
  status: string;
  expiresAt: string;
  isActive: boolean;
}

const SubscriptionGuard: React.FC<SubscriptionGuardProps> = ({ children, feature = "this feature" }) => {
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    checkSubscription();
  }, []);

  const checkSubscription = async () => {
    try {
      const response = await subscriptionAPI.getCurrentSubscription();
      setSubscription(response.data.subscription);
    } catch (error) {
      console.error('Failed to check subscription:', error);
    } finally {
      setLoading(false);
    }
  };

  const isSubscriptionActive = () => {
    if (!subscription) return false;
    return subscription.isActive && new Date(subscription.expiresAt) > new Date();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-amber-500"></div>
      </div>
    );
  }

  if (!isSubscriptionActive()) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="min-h-[400px] flex items-center justify-center p-8"
      >
        <div className="text-center max-w-md">
          <motion.div
            animate={{ rotateY: [0, 360] }}
            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
            className="w-20 h-20 bg-gradient-to-r from-amber-500 to-bronze-600 rounded-full flex items-center justify-center mx-auto mb-6 shadow-3d"
          >
            <Crown className="w-10 h-10 text-white" />
          </motion.div>
          
          <h2 className="text-2xl font-bold text-bronze-800 mb-4">
            Subscription Required
          </h2>
          
          <p className="text-bronze-600 mb-6">
            You need an active subscription to access {feature}. Choose a plan that fits your trading needs.
          </p>
          
          <div className="space-y-4">
            <motion.button
              onClick={() => navigate('/subscription')}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-3 rounded-xl font-medium flex items-center justify-center space-x-2 hover:shadow-3d-hover transition-all shadow-3d"
            >
              <Crown className="w-5 h-5" />
              <span>View Subscription Plans</span>
              <ArrowRight className="w-5 h-5" />
            </motion.button>
            
            <motion.button
              onClick={() => navigate('/dashboard')}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium hover:bg-beige-200 transition-colors border border-beige-200"
            >
              Back to Dashboard
            </motion.button>
          </div>
        </div>
      </motion.div>
    );
  }

  return <>{children}</>;
};

export default SubscriptionGuard;