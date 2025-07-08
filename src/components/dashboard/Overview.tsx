import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { TrendingUp, TrendingDown, DollarSign, Activity, Copy, CheckCircle, Bot, ExternalLink, Wifi, AlertTriangle, RefreshCw, Clock, BarChart3, Target, Zap, Crown, Lock, ArrowRight } from 'lucide-react';
import { ordersAPI, brokerAPI, subscriptionAPI } from '../../services/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';

interface Subscription {
  id: string;
  planId: string;
  planName: string;
  status: string;
  expiresAt: string;
  isActive: boolean;
}

const Overview: React.FC = () => {
  const [webhookCopied, setWebhookCopied] = useState<number | null>(null);
  const [pnlData, setPnlData] = useState<any>(null);
  const [positions, setPositions] = useState<any[]>([]);
  const [holdings, setHoldings] = useState<any[]>([]);
  const [recentOrders, setRecentOrders] = useState<any[]>([]);
  const [brokerConnections, setBrokerConnections] = useState<any[]>([]);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const [reconnectingConnection, setReconnectingConnection] = useState<number | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    checkSubscriptionAndFetchData();
  }, []);

  const checkSubscriptionAndFetchData = async () => {
    try {
      // First check subscription status
      const subscriptionResponse = await subscriptionAPI.getCurrentSubscription();
      const currentSubscription = subscriptionResponse.data.subscription;
      setSubscription(currentSubscription);

      // Check if subscription is active
      const isSubscriptionActive = currentSubscription && 
        currentSubscription.isActive && 
        new Date(currentSubscription.expiresAt) > new Date();

      if (!isSubscriptionActive) {
        // If subscription is not active, only show basic info
        setLoading(false);
        return;
      }

      // If subscription is active, fetch all data
      await fetchDashboardData();
    } catch (error) {
      console.error('Failed to check subscription:', error);
      setLoading(false);
    }
  };

  const fetchDashboardData = async () => {
    try {
      const [connectionsResponse] = await Promise.all([
        brokerAPI.getConnections()
      ]);

      const connections = connectionsResponse.data.connections;
      setBrokerConnections(connections);
      
      // Only fetch data from active and authenticated connections
      const activeConnections = connections.filter((c: any) => c.is_active && c.is_authenticated);
      
      if (activeConnections.length > 0) {
        // Fetch data in parallel
        const dataPromises = [
          ordersAPI.getPnL({ period: '1M' }).catch(() => ({ data: null })),
          fetchAllPositions(activeConnections).catch(() => []),
          fetchAllHoldings(activeConnections).catch(() => []),
          ordersAPI.getOrders({ limit: 5 }).catch(() => ({ data: { orders: [] } }))
        ];

        const [pnlResponse, allPositions, allHoldings, ordersResponse] = await Promise.all(dataPromises);

        setPnlData(pnlResponse.data);
        setPositions(allPositions);
        setHoldings(allHoldings);
        setRecentOrders(ordersResponse.data.orders);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      toast.error('Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const fetchAllPositions = async (connections: any[]) => {
    const allPositions: any[] = [];
    
    for (const connection of connections) {
      try {
        const response = await brokerAPI.getPositions(connection.id);
        if (response.data.positions && response.data.positions.length > 0) {
          const formattedPositions = response.data.positions
            .filter((pos: any) => Math.abs(pos.quantity || pos.net_quantity || 0) > 0)
            .map((pos: any) => ({
              symbol: pos.tradingsymbol || pos.symbol,
              exchange: pos.exchange || 'NSE',
              quantity: pos.quantity || pos.net_quantity || 0,
              average_price: pos.average_price || pos.buy_price || 0,
              current_price: pos.last_price || pos.ltp || 0,
              pnl: pos.pnl || pos.unrealised || 0,
              pnl_percentage: pos.pnl_percentage || 0,
              product: pos.product || 'MIS',
              broker_name: connection.broker_name,
              connection_id: connection.id
            }));
          allPositions.push(...formattedPositions);
        }
      } catch (error) {
        console.error(`Failed to fetch positions from ${connection.broker_name}:`, error);
      }
    }
    
    return allPositions;
  };

  const fetchAllHoldings = async (connections: any[]) => {
    const allHoldings: any[] = [];
    
    for (const connection of connections) {
      try {
        const response = await brokerAPI.getHoldings(connection.id);
        if (response.data.holdings && response.data.holdings.length > 0) {
          const formattedHoldings = response.data.holdings
            .filter((holding: any) => (holding.quantity || 0) > 0)
            .map((holding: any) => ({
              symbol: holding.tradingsymbol || holding.symbol,
              exchange: holding.exchange || 'NSE',
              quantity: holding.quantity || 0,
              average_price: holding.average_price || 0,
              current_price: holding.last_price || holding.ltp || 0,
              pnl: holding.pnl || 0,
              day_change: holding.day_change || 0,
              day_change_percentage: holding.day_change_percentage || 0,
              broker_name: connection.broker_name,
              connection_id: connection.id
            }));
          allHoldings.push(...formattedHoldings);
        }
      } catch (error) {
        console.error(`Failed to fetch holdings from ${connection.broker_name}:`, error);
      }
    }
    
    return allHoldings;
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
        const authWindow = window.open(
          response.data.loginUrl,
          'reconnect-auth',
          'width=600,height=700,scrollbars=yes,resizable=yes'
        );

        if (authWindow) {
          const checkClosed = setInterval(() => {
            if (authWindow.closed) {
              clearInterval(checkClosed);
              setTimeout(() => {
                checkSubscriptionAndFetchData();
              }, 2000);
            }
          }, 1000);

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
        toast.success('Reconnected successfully using stored credentials!');
        checkSubscriptionAndFetchData();
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to reconnect');
      
      if (error.response?.status === 404) {
        checkSubscriptionAndFetchData();
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

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  const isSubscriptionActive = () => {
    return subscription && subscription.isActive && new Date(subscription.expiresAt) > new Date();
  };

  const stats = [
    {
      title: 'Total P&L',
      value: `${formatCurrency(pnlData?.summary?.totalPnL || 0)}`,
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
      title: 'Total Holdings',
      value: holdings.length.toString(),
      change: `${holdings.filter(h => h.pnl > 0).length} profitable`,
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

  // Show subscription required message if not active
  if (!isSubscriptionActive()) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-4xl mx-auto"
        >
          {/* Subscription Status */}
          <motion.div
            className="bg-white/90 backdrop-blur-xl rounded-3xl p-8 border border-beige-200 shadow-3d text-center mb-8"
          >
            <motion.div
              animate={{ rotateY: [0, 360] }}
              transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
              className="w-20 h-20 bg-gradient-to-r from-amber-500 to-bronze-600 rounded-full flex items-center justify-center mx-auto mb-6 shadow-3d"
            >
              <Crown className="w-10 h-10 text-white" />
            </motion.div>
            
            <h1 className="text-3xl font-bold text-bronze-800 mb-4">
              {subscription ? 'Subscription Expired' : 'Subscription Required'}
            </h1>
            
            <p className="text-bronze-600 mb-6 max-w-2xl mx-auto">
              {subscription 
                ? `Your subscription expired on ${format(new Date(subscription.expiresAt), 'MMM dd, yyyy')}. Renew your subscription to continue using AutoTraderHub features.`
                : 'You need an active subscription to access the dashboard and trading features. Choose a plan that fits your trading needs.'
              }
            </p>

            {subscription && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6 max-w-md mx-auto">
                <h3 className="font-semibold text-red-800 mb-2">Services Deactivated</h3>
                <ul className="text-sm text-red-700 space-y-1">
                  <li>• Webhook endpoints disabled</li>
                  <li>• Real-time data updates stopped</li>
                  <li>• Order execution suspended</li>
                  <li>• Broker connections inactive</li>
                </ul>
              </div>
            )}
            
            <div className="space-y-4">
              <motion.button
                onClick={() => navigate('/subscription')}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-8 py-4 rounded-xl font-bold text-lg flex items-center justify-center space-x-2 hover:shadow-3d-hover transition-all shadow-3d mx-auto"
              >
                <Crown className="w-6 h-6" />
                <span>{subscription ? 'Renew Subscription' : 'View Subscription Plans'}</span>
                <ArrowRight className="w-6 h-6" />
              </motion.button>
              
              <motion.button
                onClick={() => navigate('/dashboard/brokers')}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="bg-beige-100 text-bronze-700 px-6 py-3 rounded-xl font-medium hover:bg-beige-200 transition-colors border border-beige-200"
              >
                Manage Broker Connections
              </motion.button>
            </div>
          </motion.div>

          {/* Limited Broker Connections View */}
          {brokerConnections.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
            >
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-bronze-800 flex items-center">
                  <Lock className="w-6 h-6 mr-2 text-amber-600" />
                  Broker Connections (Inactive)
                </h2>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {brokerConnections.map((connection, index) => {
                  const brokers = [
                    { id: 'zerodha', name: 'Zerodha', logo: '🔥' },
                    { id: 'upstox', name: 'Upstox', logo: '⚡' },
                    { id: '5paisa', name: '5Paisa', logo: '💎' }
                  ];
                  const broker = brokers.find(b => b.id === connection.broker_name.toLowerCase());
                  
                  return (
                    <motion.div
                      key={connection.id}
                      initial={{ opacity: 0, y: 30 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="bg-cream-50 rounded-2xl p-4 border border-beige-200 shadow-3d opacity-60"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div className="text-3xl opacity-50">
                            {broker?.logo || '🏦'}
                          </div>
                          <div>
                            <h3 className="font-bold text-bronze-800 capitalize">{connection.broker_name}</h3>
                            {connection.connection_name && (
                              <p className="text-xs text-bronze-600">{connection.connection_name}</p>
                            )}
                          </div>
                        </div>
                        
                        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-600">
                          <Lock className="w-3 h-3" />
                          <span>Inactive</span>
                        </div>
                      </div>

                      <div className="text-center py-4">
                        <p className="text-sm text-bronze-600 mb-3">
                          Activate subscription to use this connection
                        </p>
                        <motion.button
                          onClick={() => navigate('/subscription')}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          className="text-xs bg-amber-500 text-white px-3 py-1 rounded hover:bg-amber-600 transition-colors"
                        >
                          Activate
                        </motion.button>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </motion.div>
          )}
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 p-6 space-y-8">
      {/* Enhanced Welcome Section with Subscription Status */}
      <motion.div
        initial={{ opacity: 0, y: 20, rotateX: -10 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        className="bg-gradient-to-r from-amber-500 to-bronze-600 rounded-3xl p-8 text-white relative overflow-hidden shadow-3d"
      >
        <div className="absolute inset-0 bg-gradient-to-r from-amber-400/20 to-bronze-500/20 backdrop-blur-sm"></div>
        <div className="relative z-10 flex items-center justify-between">
          <div>
            <h1 className="text-3xl md:text-4xl font-bold mb-3">Welcome back, Trader!</h1>
            <p className="text-amber-100">Your automated trading dashboard is ready. Monitor your strategies and performance.</p>
          </div>
          
          {subscription && (
            <div className="bg-white/20 backdrop-blur-sm rounded-xl p-4 text-center">
              <div className="flex items-center space-x-2 mb-2">
                <Crown className="w-5 h-5 text-amber-200" />
                <span className="text-amber-100 font-medium">{subscription.planName}</span>
              </div>
              <p className="text-xs text-amber-200">
                Expires: {format(new Date(subscription.expiresAt), 'MMM dd, yyyy')}
              </p>
            </div>
          )}
        </div>
        
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

      {/* Enhanced Stats Grid */}
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
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-bronze-800 flex items-center">
            <Wifi className="w-6 h-6 mr-2 text-amber-600" />
            Active Broker Connections ({brokerConnections.filter(c => c.is_active).length}/5)
          </h2>
          <motion.button
            onClick={() => navigate('/dashboard/brokers')}
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
                  { id: 'zerodha', name: 'Zerodha', logo: '🔥' },
                  { id: 'upstox', name: 'Upstox', logo: '⚡' },
                  { id: '5paisa', name: '5Paisa', logo: '💎' }
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

                    <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium mb-3 ${statusInfo.bgColor} ${statusInfo.color}`}>
                      <statusInfo.icon className="w-3 h-3" />
                      <span>{statusInfo.status}</span>
                    </div>

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
              onClick={() => navigate('/dashboard/brokers')}
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
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-bronze-800 flex items-center">
              <Activity className="w-6 h-6 mr-2 text-amber-600" />
              Active Positions ({positions.length})
            </h2>
            <button 
              onClick={() => navigate('/dashboard/positions')}
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
                    <span className="text-bronze-800 font-medium">{formatCurrency(position.average_price)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Current:</span>
                    <span className="text-bronze-800 font-medium">{formatCurrency(position.current_price)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">P&L:</span>
                    <span className={`font-bold ${getPnLColor(position.pnl)}`}>
                      {position.pnl > 0 ? '+' : ''}{formatCurrency(position.pnl)}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Enhanced Holdings Section */}
      {holdings.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          whileHover={{ scale: 1.005 }}
          className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-bronze-800 flex items-center">
              <BarChart3 className="w-6 h-6 mr-2 text-amber-600" />
              Holdings ({holdings.length})
            </h2>
            <button 
              onClick={() => navigate('/dashboard/positions')}
              className="text-amber-600 hover:text-amber-500 font-medium transition-colors"
            >
              View All
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {holdings.slice(0, 6).map((holding, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                whileHover={{ scale: 1.02 }}
                className="bg-cream-50 rounded-xl p-4 border border-beige-200 shadow-3d hover:shadow-3d-hover transition-all"
              >
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-bold text-bronze-800">{holding.symbol}</h4>
                  <span className="text-sm font-medium text-blue-600">HOLDING</span>
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Qty:</span>
                    <span className="text-bronze-800 font-medium">{holding.quantity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Avg Price:</span>
                    <span className="text-bronze-800 font-medium">{formatCurrency(holding.average_price)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Current:</span>
                    <span className="text-bronze-800 font-medium">{formatCurrency(holding.current_price)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">P&L:</span>
                    <span className={`font-bold ${getPnLColor(holding.pnl)}`}>
                      {holding.pnl > 0 ? '+' : ''}{formatCurrency(holding.pnl)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-bronze-600">Day Change:</span>
                    <span className={`font-medium ${getPnLColor(holding.day_change)}`}>
                      {holding.day_change > 0 ? '+' : ''}{formatCurrency(holding.day_change)}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Enhanced Recent Orders Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.8 }}
        whileHover={{ scale: 1.005 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-bronze-800">Recent Orders</h2>
          <button 
            onClick={() => navigate('/dashboard/orders')}
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
                    <td className="py-3 px-4 text-bronze-700">{formatCurrency(order.executed_price || order.price)}</td>
                    <td className="py-3 px-4">
                      <span className={`font-medium ${getPnLColor(order.pnl)}`}>
                        {order.pnl > 0 ? '+' : ''}{formatCurrency(order.pnl)}
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
            <h3 className="text-lg font-medium text-bronze-800 mb-2">No Recent Orders</h3>
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