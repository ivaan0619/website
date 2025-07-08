import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  LayoutDashboard, 
  FileText, 
  BarChart3, 
  Link as LinkIcon, 
  Settings,
  Menu,
  X,
  Activity
} from 'lucide-react';

const DashboardLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = React.useState(false);
  const location = useLocation();

  const navigation = [
    { name: 'Overview', href: '/dashboard', icon: LayoutDashboard },
    { name: 'Orders', href: '/dashboard/orders', icon: FileText },
    { name: 'Positions', href: '/dashboard/positions', icon: Activity },
    { name: 'P&L Analytics', href: '/dashboard/pnl', icon: BarChart3 },
    { name: 'Broker Connection', href: '/dashboard/brokers', icon: LinkIcon },
    { name: 'Settings', href: '/dashboard/settings', icon: Settings },
  ];

  const isActive = (href: string) => {
    if (href === '/dashboard' && location.pathname === '/dashboard') return true;
    if (href !== '/dashboard' && location.pathname.startsWith(href)) return true;
    return false;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 pt-20">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        >
          <div className="fixed inset-0 bg-black bg-opacity-50" />
        </div>
      )}

      {/* Sidebar */}
      <div className={`
        fixed top-20 left-0 z-50 w-64 h-full bg-white/95 backdrop-blur-xl shadow-3d border-r border-beige-200 transform transition-transform duration-300 ease-in-out lg:translate-x-0
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="flex items-center justify-between p-4 border-b border-beige-200 lg:hidden">
          <span className="text-lg font-semibold text-bronze-700">Menu</span>
          <button
            onClick={() => setSidebarOpen(false)}
            className="p-2 rounded-lg text-bronze-600 hover:text-bronze-500 hover:bg-beige-100"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="p-4 space-y-2">
          {navigation.map((item) => (
            <motion.div
              key={item.name}
              whileHover={{ scale: 1.02, x: 5 }}
              whileTap={{ scale: 0.98 }}
            >
              <Link
                to={item.href}
                onClick={() => setSidebarOpen(false)}
                className={`
                  flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200 shadow-3d hover:shadow-3d-hover
                  ${isActive(item.href)
                    ? 'bg-gradient-to-r from-amber-500 to-bronze-600 text-white'
                    : 'text-bronze-700 hover:bg-beige-100 hover:text-bronze-800'
                  }
                `}
                style={{ transformStyle: 'preserve-3d' }}
              >
                <item.icon className="w-5 h-5" />
                <span className="font-medium">{item.name}</span>
              </Link>
            </motion.div>
          ))}
        </nav>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        <div className="p-4 sm:p-6 lg:p-8">
          {/* Mobile menu button */}
          <motion.button
            onClick={() => setSidebarOpen(true)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="mb-6 p-2 rounded-lg text-bronze-600 hover:text-bronze-500 hover:bg-white/50 shadow-3d lg:hidden"
          >
            <Menu className="w-6 h-6" />
          </motion.button>

          {/* Page content */}
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            <Outlet />
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default DashboardLayout;