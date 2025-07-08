import React from 'react';
import { motion } from 'framer-motion';
import { Bot, Link as LinkIcon, Shield, TrendingUp, Zap, BarChart3 } from 'lucide-react';

const Features: React.FC = () => {
  const features = [
    {
      icon: Bot,
      title: 'TradingView Integration',
      description: 'Seamlessly connect your TradingView alerts to execute trades automatically based on your strategies.',
      color: 'from-amber-500 to-bronze-600'
    },
    {
      icon: LinkIcon,
      title: 'Multi-Broker Support',
      description: 'Connect to multiple brokers including Zerodha, Upstox, and 5Paisa with secure API integration.',
      color: 'from-bronze-500 to-bronze-700'
    },
    {
      icon: Zap,
      title: 'Lightning Fast Execution',
      description: 'Execute trades in milliseconds with our optimized infrastructure and direct broker connections.',
      color: 'from-amber-600 to-bronze-600'
    },
    {
      icon: Shield,
      title: 'Enterprise Security',
      description: 'Bank-grade encryption protects your API keys and trading data with military-grade security.',
      color: 'from-bronze-600 to-bronze-800'
    },
    {
      icon: BarChart3,
      title: 'Advanced Analytics',
      description: 'Track your performance with detailed P&L reports, trade history, and comprehensive analytics.',
      color: 'from-amber-500 to-bronze-500'
    },
    {
      icon: TrendingUp,
      title: 'Real-time Monitoring',
      description: 'Monitor your automated trades in real-time with live updates and instant notifications.',
      color: 'from-bronze-500 to-amber-600'
    }
  ];

  return (
    <section className="py-20 bg-gradient-to-b from-beige-100 to-sand-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-bronze-800 mb-6">
            Powerful Features for 
            <span className="bg-gradient-to-r from-amber-600 to-bronze-700 bg-clip-text text-transparent"> Modern Traders</span>
          </h2>
          <p className="text-xl text-bronze-600 max-w-3xl mx-auto">
            Everything you need to automate your trading strategy with confidence and precision
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              viewport={{ once: true }}
              whileHover={{ 
                scale: 1.05,
                rotateY: 5,
                rotateX: 5,
              }}
              className="group bg-white/80 backdrop-blur-xl rounded-2xl p-8 shadow-3d hover:shadow-3d-hover transition-all duration-500 border border-beige-200 hover:border-amber-300"
              style={{ transformStyle: 'preserve-3d' }}
            >
              <div className={`w-16 h-16 bg-gradient-to-r ${feature.color} rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300 shadow-3d`}>
                <feature.icon className="w-8 h-8 text-white" />
              </div>
              
              <h3 className="text-xl font-bold text-bronze-800 mb-4 group-hover:text-amber-700 transition-colors">
                {feature.title}
              </h3>
              
              <p className="text-bronze-600 leading-relaxed">
                {feature.description}
              </p>

              <div className="mt-6 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                <div className={`h-1 bg-gradient-to-r ${feature.color} rounded-full transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500`}></div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Stats section */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="mt-20 bg-gradient-to-r from-amber-500 to-bronze-600 rounded-3xl p-8 md:p-12 shadow-3d"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div>
              <div className="text-4xl md:text-5xl font-bold text-white mb-2">99.9%</div>
              <div className="text-amber-100 text-lg">Uptime Guarantee</div>
            </div>
            <div>
              <div className="text-4xl md:text-5xl font-bold text-white mb-2">&lt;100ms</div>
              <div className="text-amber-100 text-lg">Average Execution Time</div>
            </div>
            <div>
              <div className="text-4xl md:text-5xl font-bold text-white mb-2">10,000+</div>
              <div className="text-amber-100 text-lg">Trades Executed Daily</div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default Features;