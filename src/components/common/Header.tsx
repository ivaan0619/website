import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { TrendingUp, User, LogOut, Crown } from 'lucide-react';
import { isAuthenticated, removeToken } from '../../utils/auth';

const Header: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const authenticated = isAuthenticated();

  const handleLogout = () => {
    removeToken();
    navigate('/');
  };

  const isLandingPage = location.pathname === '/';

  return (
    <motion.header
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isLandingPage 
          ? 'bg-cream-50/80 backdrop-blur-xl shadow-lg border-b border-beige-200/50' 
          : 'bg-cream-50/95 backdrop-blur-xl shadow-xl border-b border-beige-200'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          <Link to="/" className="flex items-center space-x-3">
            <motion.div 
              className="w-12 h-12 bg-gradient-to-br from-amber-500 to-bronze-600 rounded-2xl flex items-center justify-center shadow-3d"
              whileHover={{ 
                rotateY: 180, 
                scale: 1.1,
                boxShadow: '0 15px 30px -5px rgba(218, 143, 74, 0.4)'
              }}
              transition={{ duration: 0.6 }}
              style={{ transformStyle: 'preserve-3d' }}
            >
              <TrendingUp className="w-7 h-7 text-white" />
            </motion.div>
            <span className={`text-xl font-bold ${
              isLandingPage ? 'text-bronze-800' : 'text-bronze-700'
            }`}>
              AutoTraderHub
            </span>
          </Link>

          <nav className="hidden md:flex items-center space-x-8">
            {!authenticated ? (
              <>
                <Link
                  to="/"
                  className={`hover:text-amber-600 transition-colors font-medium ${
                    isLandingPage ? 'text-bronze-700' : 'text-bronze-600'
                  }`}
                >
                  Home
                </Link>
                <Link
                  to="/login"
                  className={`hover:text-amber-600 transition-colors font-medium ${
                    isLandingPage ? 'text-bronze-700' : 'text-bronze-600'
                  }`}
                >
                  Login
                </Link>
                <motion.div
                  whileHover={{ scale: 1.05, rotateX: 5 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Link
                    to="/register"
                    className="bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-6 py-3 rounded-xl hover:shadow-3d-hover transition-all transform font-medium shadow-3d"
                    style={{ transformStyle: 'preserve-3d' }}
                  >
                    Get Started
                  </Link>
                </motion.div>
              </>
            ) : (
              <>
                <Link
                  to="/dashboard"
                  className={`hover:text-amber-600 transition-colors font-medium ${
                    isLandingPage ? 'text-bronze-700' : 'text-bronze-600'
                  }`}
                >
                  Dashboard
                </Link>
                <Link
                  to="/subscription"
                  className={`hover:text-amber-600 transition-colors font-medium flex items-center space-x-1 ${
                    isLandingPage ? 'text-bronze-700' : 'text-bronze-600'
                  }`}
                >
                  <Crown className="w-4 h-4" />
                  <span>Subscription</span>
                </Link>
                <div className="flex items-center space-x-4">
                  <motion.div 
                    className="w-10 h-10 bg-gradient-to-br from-amber-500 to-bronze-600 rounded-full flex items-center justify-center shadow-3d"
                    whileHover={{ scale: 1.1, rotateY: 180 }}
                    transition={{ duration: 0.6 }}
                    style={{ transformStyle: 'preserve-3d' }}
                  >
                    <User className="w-5 h-5 text-white" />
                  </motion.div>
                  <motion.button
                    onClick={handleLogout}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className="flex items-center space-x-2 text-red-600 hover:text-red-500 transition-colors font-medium"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Logout</span>
                  </motion.button>
                </div>
              </>
            )}
          </nav>
        </div>
      </div>
    </motion.header>
  );
};

export default Header;