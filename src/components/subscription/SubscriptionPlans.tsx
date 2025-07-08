import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Check, Crown, Zap, Star, Calendar, CreditCard, ArrowRight, Shield, TrendingUp } from 'lucide-react';
import { subscriptionAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface Plan {
  id: string;
  name: string;
  price: number;
  duration: string;
  features: string[];
  popular?: boolean;
  icon: React.ComponentType<any>;
  color: string;
  description: string;
}

interface Subscription {
  id: string;
  planId: string;
  status: string;
  expiresAt: string;
  isActive: boolean;
}

const SubscriptionPlans: React.FC = () => {
  const [currentSubscription, setCurrentSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const [subscribing, setSubscribing] = useState<string | null>(null);

  const plans: Plan[] = [
    {
      id: 'free-trial',
      name: 'Free Trial',
      price: 0,
      duration: '1 Day',
      description: 'Perfect for testing our platform',
      icon: Star,
      color: 'from-blue-500 to-blue-600',
      features: [
        '1 Day Full Access',
        'Connect 1 Broker Account',
        'Basic Analytics',
        'Email Support',
        'Up to 10 Trades',
        'TradingView Integration'
      ]
    },
    {
      id: 'weekly',
      name: 'Weekly Plan',
      price: 100,
      duration: '7 Days',
      description: 'Great for short-term trading',
      icon: Zap,
      color: 'from-amber-500 to-orange-600',
      popular: true,
      features: [
        '7 Days Full Access',
        'Connect up to 3 Broker Accounts',
        'Advanced Analytics',
        'Priority Email Support',
        'Unlimited Trades',
        'Real-time Monitoring',
        'P&L Reports',
        'TradingView Integration'
      ]
    },
    {
      id: 'monthly',
      name: 'Monthly Plan',
      price: 300,
      duration: '30 Days',
      description: 'Best value for serious traders',
      icon: Crown,
      color: 'from-purple-500 to-purple-600',
      features: [
        '30 Days Full Access',
        'Connect up to 5 Broker Accounts',
        'Premium Analytics & Insights',
        '24/7 Priority Support',
        'Unlimited Trades',
        'Real-time Monitoring',
        'Advanced P&L Reports',
        'Custom Webhooks',
        'API Access',
        'TradingView Integration'
      ]
    }
  ];

  useEffect(() => {
    fetchCurrentSubscription();
  }, []);

  const fetchCurrentSubscription = async () => {
    try {
      const response = await subscriptionAPI.getCurrentSubscription();
      setCurrentSubscription(response.data.subscription);
    } catch (error) {
      console.error('Failed to fetch subscription:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubscribe = async (planId: string) => {
    setSubscribing(planId);
    try {
      const response = await subscriptionAPI.subscribe(planId);
      
      if (response.data.requiresPayment) {
        // For now, we'll simulate payment success
        toast.success('Payment simulation - Subscription activated!');
        await fetchCurrentSubscription();
      } else {
        toast.success('Subscription activated successfully!');
        await fetchCurrentSubscription();
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to subscribe');
    } finally {
      setSubscribing(null);
    }
  };

  const isCurrentPlan = (planId: string) => {
    return currentSubscription?.planId === planId && currentSubscription?.isActive;
  };

  const isExpired = () => {
    if (!currentSubscription) return false;
    return new Date(currentSubscription.expiresAt) < new Date();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-12"
      >
        <h1 className="text-4xl md:text-5xl font-bold text-bronze-800 mb-4">
          Choose Your 
          <span className="bg-gradient-to-r from-amber-600 to-bronze-700 bg-clip-text text-transparent"> Trading Plan</span>
        </h1>
        <p className="text-xl text-bronze-600 max-w-3xl mx-auto">
          Unlock the full potential of automated trading with our flexible subscription plans
        </p>
      </motion.div>

      {/* Current Subscription Status */}
      {currentSubscription && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={`max-w-4xl mx-auto mb-8 p-6 rounded-2xl border ${
            isExpired() 
              ? 'bg-red-50 border-red-200' 
              : 'bg-green-50 border-green-200'
          } shadow-3d`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                isExpired() ? 'bg-red-100' : 'bg-green-100'
              }`}>
                {isExpired() ? (
                  <Calendar className="w-6 h-6 text-red-600" />
                ) : (
                  <Shield className="w-6 h-6 text-green-600" />
                )}
              </div>
              <div>
                <h3 className={`font-bold ${isExpired() ? 'text-red-800' : 'text-green-800'}`}>
                  {isExpired() ? 'Subscription Expired' : 'Active Subscription'}
                </h3>
                <p className={`text-sm ${isExpired() ? 'text-red-600' : 'text-green-600'}`}>
                  {isExpired() 
                    ? `Expired on ${new Date(currentSubscription.expiresAt).toLocaleDateString()}`
                    : `Expires on ${new Date(currentSubscription.expiresAt).toLocaleDateString()}`
                  }
                </p>
              </div>
            </div>
            {isExpired() && (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-6 py-3 rounded-xl font-medium hover:shadow-3d-hover transition-all shadow-3d"
              >
                Renew Now
              </motion.button>
            )}
          </div>
        </motion.div>
      )}

      {/* Subscription Plans */}
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {plans.map((plan, index) => (
            <motion.div
              key={plan.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ 
                scale: 1.02,
                rotateY: 2,
              }}
              className={`relative bg-white/90 backdrop-blur-xl rounded-3xl p-8 border-2 transition-all duration-500 shadow-3d hover:shadow-3d-hover ${
                plan.popular 
                  ? 'border-amber-300 ring-4 ring-amber-100' 
                  : 'border-beige-200 hover:border-amber-300'
              } ${
                isCurrentPlan(plan.id) ? 'ring-4 ring-green-200 border-green-300' : ''
              }`}
              style={{ transformStyle: 'preserve-3d' }}
            >
              {/* Popular Badge */}
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                  <div className="bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-6 py-2 rounded-full text-sm font-bold shadow-3d">
                    Most Popular
                  </div>
                </div>
              )}

              {/* Current Plan Badge */}
              {isCurrentPlan(plan.id) && (
                <div className="absolute -top-4 right-4">
                  <div className="bg-gradient-to-r from-green-500 to-green-600 text-white px-4 py-2 rounded-full text-sm font-bold shadow-3d">
                    Current Plan
                  </div>
                </div>
              )}

              {/* Plan Header */}
              <div className="text-center mb-8">
                <div className={`w-20 h-20 bg-gradient-to-r ${plan.color} rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-3d`}>
                  <plan.icon className="w-10 h-10 text-white" />
                </div>
                
                <h3 className="text-2xl font-bold text-bronze-800 mb-2">{plan.name}</h3>
                <p className="text-bronze-600 mb-4">{plan.description}</p>
                
                <div className="mb-6">
                  <div className="flex items-baseline justify-center">
                    <span className="text-4xl font-bold text-bronze-800">₹{plan.price}</span>
                    {plan.price > 0 && (
                      <span className="text-bronze-600 ml-2">/{plan.duration.toLowerCase()}</span>
                    )}
                  </div>
                  {plan.price === 0 && (
                    <span className="text-bronze-600 text-sm">No credit card required</span>
                  )}
                </div>
              </div>

              {/* Features List */}
              <div className="space-y-4 mb-8">
                {plan.features.map((feature, featureIndex) => (
                  <div key={featureIndex} className="flex items-center space-x-3">
                    <div className={`w-5 h-5 bg-gradient-to-r ${plan.color} rounded-full flex items-center justify-center flex-shrink-0`}>
                      <Check className="w-3 h-3 text-white" />
                    </div>
                    <span className="text-bronze-700">{feature}</span>
                  </div>
                ))}
              </div>

              {/* Subscribe Button */}
              <motion.button
                onClick={() => handleSubscribe(plan.id)}
                disabled={subscribing === plan.id || isCurrentPlan(plan.id)}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={`w-full py-4 rounded-xl font-bold text-lg transition-all shadow-3d hover:shadow-3d-hover flex items-center justify-center space-x-2 ${
                  isCurrentPlan(plan.id)
                    ? 'bg-green-100 text-green-700 cursor-not-allowed'
                    : `bg-gradient-to-r ${plan.color} text-white hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed`
                }`}
              >
                {subscribing === plan.id ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Processing...</span>
                  </>
                ) : isCurrentPlan(plan.id) ? (
                  <>
                    <Check className="w-5 h-5" />
                    <span>Current Plan</span>
                  </>
                ) : (
                  <>
                    <span>{plan.price === 0 ? 'Start Free Trial' : 'Subscribe Now'}</span>
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </motion.button>

              {/* Payment Note */}
              {plan.price > 0 && !isCurrentPlan(plan.id) && (
                <p className="text-center text-bronze-500 text-sm mt-4">
                  <CreditCard className="w-4 h-4 inline mr-1" />
                  Payment options will be available soon
                </p>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* Features Comparison */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="max-w-6xl mx-auto mt-16 bg-white/90 backdrop-blur-xl rounded-3xl p-8 border border-beige-200 shadow-3d"
      >
        <h2 className="text-3xl font-bold text-bronze-800 text-center mb-8">
          Why Choose AutoTraderHub?
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="text-center">
            <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-3d">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <h3 className="font-bold text-bronze-800 mb-2">Secure & Reliable</h3>
            <p className="text-bronze-600">Bank-grade security with 99.9% uptime guarantee</p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-gradient-to-r from-amber-500 to-orange-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-3d">
              <Zap className="w-8 h-8 text-white" />
            </div>
            <h3 className="font-bold text-bronze-800 mb-2">Lightning Fast</h3>
            <p className="text-bronze-600">Execute trades in under 100ms with our optimized infrastructure</p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-gradient-to-r from-purple-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-3d">
              <TrendingUp className="w-8 h-8 text-white" />
            </div>
            <h3 className="font-bold text-bronze-800 mb-2">Advanced Analytics</h3>
            <p className="text-bronze-600">Comprehensive P&L tracking and performance insights</p>
          </div>
        </div>
      </motion.div>

      {/* FAQ Section */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="max-w-4xl mx-auto mt-16 bg-white/90 backdrop-blur-xl rounded-3xl p-8 border border-beige-200 shadow-3d"
      >
        <h2 className="text-3xl font-bold text-bronze-800 text-center mb-8">
          Frequently Asked Questions
        </h2>
        
        <div className="space-y-6">
          <div>
            <h3 className="font-bold text-bronze-800 mb-2">Can I cancel my subscription anytime?</h3>
            <p className="text-bronze-600">Yes, you can cancel your subscription at any time. You'll continue to have access until the end of your billing period.</p>
          </div>
          
          <div>
            <h3 className="font-bold text-bronze-800 mb-2">What happens after my free trial ends?</h3>
            <p className="text-bronze-600">After your free trial ends, you'll need to subscribe to a paid plan to continue using the platform. Your data and settings will be preserved.</p>
          </div>
          
          <div>
            <h3 className="font-bold text-bronze-800 mb-2">Do you offer refunds?</h3>
            <p className="text-bronze-600">We offer a 7-day money-back guarantee for all paid subscriptions. Contact our support team for assistance.</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default SubscriptionPlans;