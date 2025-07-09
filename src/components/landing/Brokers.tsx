import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle } from 'lucide-react';

const Brokers: React.FC = () => {
  const brokers = [
    {
      name: 'Zerodha',
      logo: '🔥',
      description: 'India\'s largest stockbroker with advanced API support',
      features: ['Real-time data', 'Options trading', 'Commodity trading']
    },
    {
      name: 'Upstox',
      logo: '⚡',
      description: 'Next-generation trading platform with lightning-fast execution',
      features: ['Real-time execution', 'Advanced API', 'Multi-asset trading']
    },
    {
      name: '5Paisa',
      logo: '💎',
      description: 'Cost-effective trading with comprehensive market access',
      features: ['Low brokerage', 'Research reports', 'Investment advisory']
    }
  ];

  return (
    <section className="py-20 bg-gradient-to-b from-sand-200 to-beige-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-bronze-800 mb-6">
            Supported 
            <span className="bg-gradient-to-r from-amber-600 to-bronze-700 bg-clip-text text-transparent"> Brokers</span>
          </h2>
          <p className="text-xl text-bronze-600 max-w-3xl mx-auto">
            Connect with India's leading brokers and start automating your trades today
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
          {brokers.map((broker, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.2 }}
              viewport={{ once: true }}
              whileHover={{ 
                scale: 1.05,
                rotateY: 5,
                rotateX: 5,
              }}
              className="group bg-white/80 backdrop-blur-xl rounded-2xl p-8 hover:shadow-3d-hover transition-all duration-500 border border-beige-200 hover:border-amber-300 shadow-3d"
              style={{ transformStyle: 'preserve-3d' }}
            >
              <div className="text-center mb-6">
                <div className="text-6xl mb-4 group-hover:scale-110 transition-transform duration-300">
                  {broker.logo}
                </div>
                <h3 className="text-2xl font-bold text-bronze-800 mb-2 group-hover:text-amber-700 transition-colors">
                  {broker.name}
                </h3>
                <p className="text-bronze-600 mb-6">
                  {broker.description}
                </p>
              </div>

              <div className="space-y-3">
                {broker.features.map((feature, featureIndex) => (
                  <div key={featureIndex} className="flex items-center space-x-3">
                    <CheckCircle className="w-5 h-5 text-amber-600 flex-shrink-0" />
                    <span className="text-bronze-700">{feature}</span>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-6 border-t border-beige-200">
                <div className="text-center text-bronze-600 font-medium">
                  Available in Dashboard
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="text-center bg-white/80 backdrop-blur-xl rounded-2xl p-8 border border-beige-200 shadow-3d"
        >
          <h3 className="text-2xl font-bold text-bronze-800 mb-4">
            More Brokers Coming Soon
          </h3>
          <p className="text-bronze-600 mb-6">
            We're constantly expanding our broker integrations to give you more options
          </p>
          <div className="flex justify-center space-x-4 text-4xl opacity-50">
            <span>🏦</span>
            <span>📈</span>
            <span>💹</span>
            <span>🚀</span>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default Brokers;