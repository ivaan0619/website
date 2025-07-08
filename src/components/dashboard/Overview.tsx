import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { TrendingUp, TrendingDown, DollarSign, Activity, Copy, CheckCircle, Bot, ExternalLink, Wifi, AlertTriangle, RefreshCw, Clock, BarChart3, Target, Zap } from 'lucide-react';
import { ordersAPI, brokerAPI } from '../../services/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';

const Overview: React.FC = () => {
  const [webhookCopied, setWebhookCopied] = useState<number | null>(null);
  const [pnlData, setPnlData] = useState<any>(null);
  const [positions, setPositions] = useState<any[]>([]);
  const [recentOrders, setRecentOrders] = useState<any[]>([]);
  const [brokerConnections, setBrokerConnections] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [reconnectingConnection, setReconnectingConnection] = useState<number | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [pnlResponse, positionsResponse, ordersResponse, connectionsResponse] = await Promise.all([
        ordersAPI.getPnL({ period: '1M' }),
        ordersAPI.getPositions(),
        ordersAPI.getOrders({ limit: 5 }),
        brokerAPI.getConnections()
      ]);

      setPnlData(pnlResponse.data);
      setPositions(positionsResponse.data.positions);
      setRecentOrders(ordersResponse.data.orders);
      const connections = connectionsResponse.data.connections;
      setBrokerConnections(connections);
      
      console.log('=== BROKER CONNECTIONS DEBUG ===');
      console.log('All connections:', connections);
      console.log('Active connections:', connections.filter(c => c.is_active));
      console.log('Active connections with webhook:', connections.filter(c => c.is_active && c.webhook_url));
      console.log('Has active connection with webhook:', connections.some(c => c.is_active && c.webhook_url));
      console.log('================================');
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const copyWebhookUrl = (webhookUrl: string, connectionId: number) => {
    navigator.clipboard.writeText(webhookUrl);
    setWebhookCopied(connectionId);
    toast.success('Webhook URL copied!');
    setTimeout(() => setWebhookCopied(null), 2000);
  };

  const handleReconnectNow = async (connectionId: number) => {
    setReconnectingConnection(connectionId);
    try {
      const response = await brokerAPI.reconnect(connectionId);
      
      if (response.data.loginUrl) {
        // Open authentication window
        const authWindow = window.open(
          response.data.loginUrl,
          'reconnect-auth',
          'width=600,height=700,scrollbars=yes,resizable=yes'
        );

        if (authWindow) {
          // Check if window is closed every second
          const checkClosed = setInterval(() => {
            if (authWindow.closed) {
              clearInterval(checkClosed);
              // Refresh connections to see if auth was completed
              setTimeout(() => {
                fetchDashboardData();
              }, 2000);
            }
          }, 1000);

          // Auto-close check after 5 minutes
          setTimeout(() => {
            if (!authWindow.closed) {
              authWindow.close();
              clearInterval(checkClosed);
            }
          }, 300000);
        } else {
          toast.error('Failed to open authentication window. Please check your popup blocker.');
        }
      } else {
        // Direct reconnection successful
        toast.success('Reconnected successfully using stored credentials!');
        fetchDashboardData();
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to reconnect');
      
      // If it's a 404 error, refresh dashboard data to update UI state
      if (error.response?.status === 404) {
        fetchDashboardData();
      }
    } finally {
      setReconnectingConnection(null);
    }
  };

  const getConnectionStatusInfo = (connection: any) => {
    const now = Math.floor(Date.now() / 1000);
    
    if (!connection.is_authenticated) {
      return {
        status: 'Not Authenticated',
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: AlertTriangle,
        action: 'authenticate'
      };
    }
    
    if (connection.token_expired) {
      return {
        status: 'Token Expired',
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: AlertTriangle,
        action: 'reconnect'
      };
    }
    
    if (connection.needs_token_refresh) {
      const hoursLeft = Math.floor((connection.access_token_expires_at - now) / 3600);
      return {
        status: `Expires in ${hoursLeft}h`,
        color: 'text-amber-600',
        bgColor: 'bg-amber-100',
        icon: Clock,
        action: 'reconnect'
      };
    }
    
    return {
      status: 'Connected',
      color: 'text-green-600',
      bgColor: 'bg-green-100',
      icon: CheckCircle,
      action: null
    };
  };

  const getPnLColor = (pnl: number) => {
    if (pnl > 0) return 'text-green-600';
    if (pnl < 0) return 'text-red-600';
    return 'text-bronze-600';
  };

  const stats = [
    {
      title: 'Total P&L',
      value: `₹${pnlData?.summary?.totalPnL?.toLocaleString() || '0'}`,
      change: '+12.3%',
      trend: 'up',
      icon: DollarSign,
      color: 'from-amber-500 to-bronze-600'
    },
    {
      title: 'Win Rate',
      value: `${pnlData?.summary?.winRate || '0'}%`,
      change: '+2.1%',
      trend: 'up',
      icon: Target,
      color: 'from-green-500 to-green-600'
    },
    {
      title: 'Active Positions',
      value: positions.length.toString(),
      change: `${positions.filter(p => p.pnl > 0).length} profitable`,
      trend: 'neutral',
      icon: Activity,
      color: 'from-blue-500 to-blue-600'
    },
    {
      title: 'Total Trades',
      value: pnlData?.summary?.totalTrades?.toString() || '0',
      change: 'This month',
      trend: 'up',
      icon: BarChart3,
      color: 'from-purple-500 to-purple-600'
    }
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 p-6 space-y-8">
      {/* Enhanced Welcome Section with 3D Effects */}
      <motion.div
        initial={{ opacity: 0, y: 20, rotateX: -10 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        className="bg-gradient-to-r from-amber-500 to-bronze-600 rounded-3xl p-8 text-white relative overflow-hidden shadow-3d"
        style={{ 
          transformStyle: 'preserve-3d',
        }}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-amber-400/20 to-bronze-500/20 backdrop-blur-sm"></div>
        <div className="relative z-10">
          <h1 className="text-3xl md:text-4xl font-bold mb-3">Welcome back, Trader!</h1>
          <p className="text-amber-100">Your automated trading dashboard is ready. Monitor your strategies and performance.</p>
        </div>
        
        {/* 3D Floating Elements */}
        <motion.div
          animate={{ 
            rotateY: [0, 360],
            y: [0, -10, 0]
          }}
          transition={{ 
            duration: 10, 
            repeat: Infinity,
            ease: "linear"
          }}
          className="absolute top-4 right-4 w-16 h-16 bg-amber-400/20 rounded-full backdrop-blur-sm"
          style={{ transform: 'perspective(1000px) rotateX(45deg)' }}
        />
      </motion.div>

      {/* Enhanced Stats Grid with 3D Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, y: 20, rotateY: -15 }}
            animate={{ opacity: 1, y: 0, rotateY: 0 }}
            transition={{ delay: index * 0.1, duration: 0.6 }}
            whileHover={{ 
              scale: 1.05,
              rotateY: 5,
              rotateX: 5,
            }}
            className="group bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 hover:border-amber-300 transition-all duration-500 shadow-3d hover:shadow-3d-hover"
            style={{ 
              transformStyle: 'preserve-3d',
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <motion.div 
                className={`w-14 h-14 bg-gradient-to-r ${stat.color} rounded-xl flex items-center justify-center shadow-3d group-hover:animate-bounce-3d`}
                whileHover={{ rotateY: 180 }}
                transition={{ duration: 0.6 }}
              >
                <stat.icon className="w-7 h-7 text-white" />
              </motion.div>
              <div className={`text-sm font-medium px-3 py-1 rounded-full ${
                stat.trend === 'up' ? 'text-green-600 bg-green-100' :
                stat.trend === 'down' ? 'text-red-600 bg-red-100' :
                'text-bronze-600 bg-beige-100'
              }`}>
                {stat.change}
              </div>
            </div>
            <h3 className="text-2xl font-bold text-bronze-800 mb-1 group-hover:text-amber-700 transition-colors">{stat.value}</h3>
            <p className="text-bronze-600">{stat.title}</p>
          </motion.div>
        ))}
      </div>

      {/* Enhanced Broker Connections Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        whileHover={{ scale: 1.01, rotateX: 2 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
        style={{ 
          transformStyle: 'preserve-3d',
        }}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-bronze-800 flex items-center">
            <Wifi className="w-6 h-6 mr-2 text-amber-600" />
            Broker Connections ({brokerConnections.filter(c => c.is_active).length}/5)
          </h2>
          <motion.button
            onClick={() => window.location.href = '/dashboard/brokers'}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="text-amber-600 hover:text-amber-500 text-sm font-medium transition-colors"
          >
            Manage Connections
          </motion.button>
        </div>
        
        {brokerConnections.some(connection => connection.is_active) ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {brokerConnections
              .filter(connection => connection.is_active)
              .map((connection, index) => {
                const brokers = [
                  { 
                    id: 'zerodha', 
                    name: 'Zerodha', 
                    logo: '🔥', 
                  },
                  { 
                    id: 'upstox', 
                    name: 'Upstox', 
                    logo: '⚡', 
                  },
                  { 
                    id: '5paisa', 
                    name: '5Paisa', 
                    logo: '💎', 
                  }
                ];
                const broker = brokers.find(b => b.id === connection.broker_name.toLowerCase());
                const statusInfo = getConnectionStatusInfo(connection);
                
                return (
                  <motion.div
                    key={connection.id}
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    whileHover={{ scale: 1.02, rotateY: 2 }}
                    className="bg-cream-50 rounded-2xl p-4 border border-beige-200 shadow-3d hover:shadow-3d-hover transition-all"
                    style={{ transformStyle: 'preserve-3d' }}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <div className="text-3xl">
                          {broker?.logo || '🏦'}
                        </div>
                        <div>
                          <h3 className="font-bold text-bronze-800 capitalize">{connection.broker_name}</h3>
                          {connection.connection_name && (
                            <p className="text-xs text-bronze-600">{connection.connection_name}</p>
                          )}
                        </div>
                      </div>
                      
                      {statusInfo.action && (
                        <motion.button
                          onClick={() => statusInfo.action === 'reconnect' ? handleReconnectNow(connection.id) : null}
                          disabled={reconnectingConnection === connection.id}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          className="text-xs bg-amber-500 text-white px-2 py-1 rounded hover:bg-amber-600 transition-colors disabled:opacity-50 shadow-3d"
                        >
                          {reconnectingConnection === connection.id ? (
                            <RefreshCw className="w-3 h-3 animate-spin" />
                          ) : (
                            statusInfo.action === 'reconnect' ? 'Reconnect' : 'Auth'
                          )}
                        </motion.button>
                      )}
                    </div>

                    {/* Connection Status */}
                    <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium mb-3 ${statusInfo.bgColor} ${statusInfo.color}`}>
                      <statusInfo.icon className="w-3 h-3" />
                      <span>{statusInfo.status}</span>
                    </div>

                    {/* Webhook URL */}
                    {connection.webhook_url && (
                      <div className="mt-3">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-bronze-600">Webhook URL:</span>
                          <motion.button
                            onClick={() => copyWebhookUrl(connection.webhook_url, connection.id)}
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            className="text-amber-600 hover:text-amber-500"
                          >
                            {webhookCopied === connection.id ? (
                              <CheckCircle className="w-4 h-4" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </motion.button>
                        </div>
                        <code className="text-xs text-bronze-700 break-all block bg-beige-50 p-2 rounded">
                          {connection.webhook_url.length > 50 
                            ? `${connection.webhook_url.substring(0, 50)}...`
                            : connection.webhook_url
                          }
                        </code>
                      </div>
                    )}
                  </motion.div>
                );
              })}
          </div>
        ) : (
          <div className="text-center py-8">
            <Wifi className="w-16 h-16 text-amber-400/50 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-bronze-800 mb-2">No Active Broker Connections</h3>
            <p className="text-bronze-600 mb-4">
              Connect a broker account to see active connections here. You can connect up to 5 broker accounts.
            </p>
            <motion.button
              onClick={() => window.location.href = '/dashboard/brokers'}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="inline-flex items-center space-x-2 bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-6 py-3 rounded-xl font-medium hover:shadow-3d-hover transition-all shadow-3d"
            >
              <ExternalLink className="w-4 h-4" />
              <span>Connect Broker</span>
            </motion.button>
          </div>
        )}
      </motion.div>

      {/* Enhanced Positions Section */}
      {positions.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          whileHover={{ scale: 1.005 }}
          className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
          style={{ 
            transformStyle: 'preserve-3d',
          }}
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-bronze-800 flex items-center">
              <Activity className="w-6 h-6 mr-2 text-amber-600" />
              Active Positions
            </h2>
            <button 
              onClick={() => window.location.href = '/dashboard/orders'}
              className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
            >
              View All
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {positions.slice(0, 6).map((position, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                whileHover={{ scale: 1.02 }}
                className="bg-cream-50 rounded-xl p-4 border border-beige-200 shadow-3d hover:shadow-3d-hover transition-all"
              >
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-bold text-bronze-800">{position.symbol}</h4>
                  <span className={`text-sm font-medium ${
                    position.quantity > 0 ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {position.quantity > 0 ? 'LONG' : 'SHORT'}
                  </span>
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Qty:</span>
                    <span className="text-bronze-800 font-medium">{Math.abs(position.quantity)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Avg Price:</span>
                    <span className="text-bronze-800 font-medium">₹{position.average_price}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Current:</span>
                    <span className="text-bronze-800 font-medium">₹{position.current_price}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">P&L:</span>
                    <span className={`font-bold ${getPnLColor(position.pnl)}`}>
                      {position.pnl > 0 ? '+' : ''}₹{position.pnl}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Enhanced Recent Trades Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        whileHover={{ scale: 1.005 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
        style={{ 
          transformStyle: 'preserve-3d',
        }}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-bronze-800">Recent Trades</h2>
          <button 
            onClick={() => window.location.href = '/dashboard/orders'}
            className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
          >
            View All
          </button>
        </div>
        
        {recentOrders.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-beige-200">
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Symbol</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Type</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Qty</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Price</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">P&L</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Status</th>
                  <th className="text-left py-3 px-4 font-semibold text-bronze-700">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentOrders.map((order, index) => (
                  <motion.tr 
                    key={order.id} 
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="border-b border-beige-100 hover:bg-beige-50 transition-colors"
                  >
                    <td className="py-3 px-4 font-medium text-bronze-800">{order.symbol}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        order.transaction_type === 'BUY' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                      }`}>
                        {order.transaction_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-bronze-700">{order.quantity}</td>
                    <td className="py-3 px-4 text-bronze-700">₹{order.executed_price || order.price}</td>
                    <td className="py-3 px-4">
                      <span className={`font-medium ${getPnLColor(order.pnl)}`}>
                        {order.pnl > 0 ? '+' : ''}₹{order.pnl}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        order.status === 'COMPLETE' ? 'bg-green-100 text-green-700' :
                        order.status === 'OPEN' ? 'bg-amber-100 text-amber-700' :
                        'bg-beige-100 text-bronze-700'
                      }`}>
                        {order.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-bronze-600 text-sm">
                      {format(new Date(order.created_at), 'MMM dd, HH:mm')}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <TrendingUp className="w-16 h-16 text-amber-400/50 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-bronze-800 mb-2">No Recent Trades</h3>
            <p className="text-bronze-600">
              Your recent trading activity will appear here once you start placing orders.
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default Overview;