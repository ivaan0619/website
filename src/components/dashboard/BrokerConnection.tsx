import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { 
  Link, Shield, CheckCircle, AlertCircle, Settings, Zap, 
  ExternalLink, Copy, RefreshCw, Activity, TrendingUp,
  Wifi, WifiOff, TestTube, Eye, EyeOff, Plus, Key, Edit3,
  Trash2, Clock, AlertTriangle
} from 'lucide-react';
import { brokerAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface BrokerConnectionForm {
  brokerName: string;
  apiKey: string;
  apiSecret: string;
  userId: string;
  connectionName: string;
}

interface BrokerConnection {
  id: number;
  broker_name: string;
  connection_name: string;
  is_active: boolean;
  is_authenticated: boolean;
  token_expired: boolean;
  needs_token_refresh: boolean;
  access_token_expires_at: number;
  created_at: string;
  last_sync: string;
  webhook_url: string;
  user_id_broker?: string;
}

const BrokerConnection: React.FC = () => {
  const [connections, setConnections] = useState<BrokerConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showApiSecret, setShowApiSecret] = useState(false);
  const [authenticationStep, setAuthenticationStep] = useState<{connectionId: number, loginUrl: string} | null>(null);
  const [copiedWebhook, setCopiedWebhook] = useState<number | null>(null);
  const [syncingConnection, setSyncingConnection] = useState<number | null>(null);
  const [testingConnection, setTestingConnection] = useState<number | null>(null);
  const [showConnectionForm, setShowConnectionForm] = useState(false);
  const [selectedBrokerForConnection, setSelectedBrokerForConnection] = useState<string>('');
  const [reconnectingConnection, setReconnectingConnection] = useState<number | null>(null);
  const [editingConnection, setEditingConnection] = useState<BrokerConnection | null>(null);
  const [showEditForm, setShowEditForm] = useState(false);
  const [deletingConnection, setDeletingConnection] = useState<number | null>(null);
  
  const { register, handleSubmit, watch, reset, setValue, formState: { errors } } = useForm<BrokerConnectionForm>();
  const selectedBroker = watch('brokerName');

  const brokers = [
    { 
      id: 'zerodha', 
      name: 'Zerodha', 
      logo: '🔥', 
      description: 'India\'s largest stockbroker with advanced API support',
      features: ['Real-time data', 'Options trading', 'Commodity trading'],
      authRequired: true
    },
    { 
      id: 'upstox', 
      name: 'Upstox', 
      logo: '⚡', 
      description: 'Next-generation trading platform with lightning-fast execution',
      features: ['Mobile trading', 'Advanced charts', 'Margin trading'],
      authRequired: true
    },
    { 
      id: '5paisa', 
      name: '5Paisa', 
      logo: '💎', 
      description: 'Cost-effective trading with comprehensive market access',
      features: ['Low brokerage', 'Research reports', 'Investment advisory'],
      authRequired: false
    }
  ];

  useEffect(() => {
    fetchConnections();
  }, []);

  const fetchConnections = async () => {
    try {
      setLoading(true);
      const response = await brokerAPI.getConnections();
      setConnections(response.data.connections);
    } catch (error) {
      console.error('Failed to fetch connections:', error);
      toast.error('Failed to fetch broker connections');
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = async (data: BrokerConnectionForm) => {
    setIsSubmitting(true);
    try {
      const response = await brokerAPI.connect(data);
      
      if (response.data.requiresAuth && response.data.loginUrl) {
        setAuthenticationStep({
          connectionId: response.data.connectionId,
          loginUrl: response.data.loginUrl
        });
        toast.success('Credentials saved! Please complete authentication.');
      } else {
        toast.success('Broker connected successfully!');
        reset();
        setShowConnectionForm(false);
        setSelectedBrokerForConnection('');
        fetchConnections();
      }
    } catch (error: any) {
      console.error('Broker connection error:', error);
      const errorMessage = error.response?.data?.error || 'Failed to connect broker';
      toast.error(errorMessage);
      
      if (error.response?.data?.errors) {
        const errors = error.response.data.errors;
        Object.keys(errors).forEach(key => {
          toast.error(`${key}: ${errors[key]}`);
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const onEditSubmit = async (data: BrokerConnectionForm) => {
    if (!editingConnection) return;
    
    setIsSubmitting(true);
    try {
      const response = await brokerAPI.connect({
        ...data,
        brokerName: editingConnection.broker_name
      });
      
      if (response.data.requiresAuth && response.data.loginUrl) {
        setAuthenticationStep({
          connectionId: response.data.connectionId,
          loginUrl: response.data.loginUrl
        });
        toast.success('Credentials updated! Please complete authentication.');
      } else {
        toast.success('Broker connection updated successfully!');
        setShowEditForm(false);
        setEditingConnection(null);
        reset();
        fetchConnections();
      }
    } catch (error: any) {
      console.error('Broker update error:', error);
      toast.error(error.response?.data?.error || 'Failed to update broker connection');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConnectClick = (brokerId: string) => {
    setSelectedBrokerForConnection(brokerId);
    setValue('brokerName', brokerId);
    setValue('apiKey', '');
    setValue('apiSecret', '');
    setValue('userId', '');
    setValue('connectionName', '');
    setShowConnectionForm(true);
  };

  const handleEditConnection = async (connection: BrokerConnection) => {
    try {
      const response = await brokerAPI.getConnection(connection.id);
      const connectionDetails = response.data.connection;
      
      setEditingConnection(connection);
      setValue('brokerName', connection.broker_name);
      setValue('apiKey', '');
      setValue('apiSecret', '');
      setValue('userId', connectionDetails.user_id_broker || '');
      setValue('connectionName', connection.connection_name || '');
      setShowEditForm(true);
    } catch (error: any) {
      console.error('Failed to fetch connection details:', error);
      toast.error('Failed to load connection details');
    }
  };

  const handleZerodhaAuth = (connectionId: number, loginUrl: string) => {
    setReconnectingConnection(connectionId);
    
    const authWindow = window.open(
      loginUrl,
      'zerodha-auth',
      'width=600,height=700,scrollbars=yes,resizable=yes'
    );

    if (authWindow) {
      const checkClosed = setInterval(() => {
        if (authWindow.closed) {
          clearInterval(checkClosed);
          setTimeout(() => {
            fetchConnections();
            setAuthenticationStep(null);
            setReconnectingConnection(null);
          }, 2000);
        }
      }, 1000);

      setTimeout(() => {
        if (!authWindow.closed) {
          authWindow.close();
          clearInterval(checkClosed);
          setReconnectingConnection(null);
        }
      }, 300000);
    } else {
      setReconnectingConnection(null);
      toast.error('Failed to open authentication window. Please check your popup blocker.');
    }
  };

  const handleReconnectNow = async (connectionId: number) => {
    try {
      setReconnectingConnection(connectionId);
      const response = await brokerAPI.reconnect(connectionId);
      
      if (response.data.loginUrl) {
        toast.success(`Please complete authentication to reconnect your ${response.data.brokerName} account.`);
      } else {
        toast.success('Reconnected successfully using stored credentials!');
        fetchConnections();
        setReconnectingConnection(null);
      }
    } catch (error: any) {
      console.error('Reconnection failed:', error);
      
      if (error.response?.status === 404) {
        toast.error('Connection not found. Please add the broker again.');
        fetchConnections();
      } else if (error.response?.status === 401) {
        toast.error('Session expired. Please re-authenticate.');
      } else if (error.response?.status === 400) {
        const errorData = error.response.data;
        if (errorData.needsCredentials) {
          toast.error('Missing or corrupted credentials. Please update your connection settings.');
        } else {
          toast.error(errorData.error || 'Failed to reconnect');
        }
      } else if (error.response?.status === 500 && error.response?.data?.error?.includes('decrypt')) {
        toast.error('Stored credentials are corrupted. Please update your connection settings.');
      } else {
        toast.error(error.response?.data?.error || 'Failed to reconnect. Please try again.');
      }
      setReconnectingConnection(null);
    }
  };

  const disconnectBroker = async (connectionId: number) => {
    if (!confirm('Are you sure you want to disconnect this broker?')) return;

    try {
      await brokerAPI.disconnect(connectionId);
      toast.success('Broker disconnected successfully!');
      setConnections(prev => prev.map(conn => 
        conn.id === connectionId ? { ...conn, is_active: false } : conn
      ));
      fetchConnections();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to disconnect broker');
    }
  };

  const deleteBrokerConnection = async (connectionId: number) => {
    if (!confirm('Are you sure you want to permanently delete this broker connection? This action cannot be undone.')) return;

    setDeletingConnection(connectionId);
    try {
      await brokerAPI.deleteConnection(connectionId);
      toast.success('Broker connection deleted successfully!');
      fetchConnections();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to delete broker connection');
    } finally {
      setDeletingConnection(null);
    }
  };

  const copyWebhookUrl = async (webhookUrl: string, connectionId: number) => {
    try {
      await navigator.clipboard.writeText(webhookUrl);
      setCopiedWebhook(connectionId);
      toast.success('Webhook URL copied to clipboard!');
      setTimeout(() => setCopiedWebhook(null), 2000);
    } catch (err) {
      toast.error('Failed to copy webhook URL');
    }
  };

  const syncPositions = async (connectionId: number) => {
    setSyncingConnection(connectionId);
    try {
      await brokerAPI.syncPositions(connectionId);
      toast.success('Positions synced successfully!');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to sync positions');
    } finally {
      setSyncingConnection(null);
    }
  };

  const testConnection = async (connectionId: number) => {
    setTestingConnection(connectionId);
    try {
      const response = await brokerAPI.testConnection(connectionId);
      toast.success(`Connection test successful! Connected as ${response.data.profile.user_name}`);
    } catch (error: any) {
      if (error.response?.data?.tokenExpired || error.response?.data?.needsAuth) {
        toast.error('Access token expired. Please reconnect your account.');
      } else {
        toast.error(error.response?.data?.error || 'Connection test failed');
      }
    } finally {
      setTestingConnection(null);
    }
  };

  const getConnectionStatusInfo = (connection: BrokerConnection) => {
    const now = Math.floor(Date.now() / 1000);
    
    if (!connection.is_active) {
      return {
        status: 'Disconnected',
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: WifiOff,
        needsReconnect: true
      };
    }

    if (!connection.is_authenticated) {
      return {
        status: 'Not Authenticated',
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: AlertTriangle,
        needsReconnect: true
      };
    }
    
    if (connection.token_expired) {
      return {
        status: 'Token Expired',
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: AlertTriangle,
        needsReconnect: true
      };
    }
    
    if (connection.needs_token_refresh) {
      const hoursLeft = Math.floor((connection.access_token_expires_at - now) / 3600);
      return {
        status: `Expires in ${hoursLeft}h`,
        color: 'text-amber-600',
        bgColor: 'bg-amber-100',
        icon: Clock,
        needsReconnect: true
      };
    }
    
    return {
      status: 'Connected',
      color: 'text-green-600',
      bgColor: 'bg-green-100',
      icon: Wifi,
      needsReconnect: false
    };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-cream-50 to-beige-100 p-6 space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20, rotateX: -10 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl md:text-4xl font-bold text-bronze-800 mb-2">Broker Connections</h1>
          <p className="text-bronze-600">Connect your broker accounts to enable automated trading</p>
        </div>
        <motion.button
          onClick={() => {
            setShowConnectionForm(true);
            setSelectedBrokerForConnection('');
            reset();
          }}
          whileHover={{ scale: 1.05, rotateX: 5 }}
          whileTap={{ scale: 0.95 }}
          className="mt-4 sm:mt-0 bg-gradient-to-r from-amber-500 to-bronze-600 text-white px-6 py-3 rounded-xl font-medium flex items-center space-x-2 hover:shadow-3d-hover transition-all shadow-3d"
        >
          <Plus className="w-5 h-5" />
          <span>Add Broker</span>
        </motion.button>
      </motion.div>

      {/* Security Notice */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity : 1, y: 0 }}
        transition={{ delay: 0.1 }}
        whileHover={{ scale: 1.01, rotateX: 2 }}
        className="bg-white/80 backdrop-blur-xl border border-beige-200 rounded-2xl p-6 shadow-3d"
      >
        <div className="flex items-start space-x-4">
          <motion.div
            animate={{ rotateY: [0, 360] }}
            transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
          >
            <Shield className="w-8 h-8 text-amber-600 flex-shrink-0 mt-1" />
          </motion.div>
          <div>
            <h3 className="font-bold text-bronze-800 mb-2 text-lg">Your Security is Our Priority</h3>
            <p className="text-bronze-600">
              All API keys are encrypted using AES-256 encryption and stored securely. 
              We never store your login credentials and only use read-only permissions where possible.
            </p>
          </div>
        </div>
      </motion.div>

      {/* Connected Brokers Section */}
      {connections.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
        >
          <h2 className="text-2xl font-bold text-bronze-800 mb-6 flex items-center">
            <Wifi className="w-6 h-6 mr-2 text-amber-600" />
            Connected Brokers ({connections.filter(c => c.is_active).length})
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {connections.map((connection, index) => {
              const broker = brokers.find(b => b.id === connection.broker_name.toLowerCase());
              const statusInfo = getConnectionStatusInfo(connection);
              
              return (
                <motion.div
                  key={connection.id}
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                  whileHover={{ scale: 1.02, rotateY: 2 }}
                  className="bg-cream-50 rounded-2xl p-6 border border-beige-200 shadow-3d hover:shadow-3d-hover transition-all"
                >
                  {/* Connection Header */}
                  <div className="text-center mb-4">
                    <div className="text-4xl mb-3">{broker?.logo || '🏦'}</div>
                    <h3 className="font-bold text-bronze-800 text-lg capitalize">
                      {connection.broker_name}
                    </h3>
                    {connection.connection_name && (
                      <p className="text-sm text-bronze-600 mt-1">{connection.connection_name}</p>
                    )}
                    <div className="flex items-center justify-center space-x-2 mt-2">
                      <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium ${statusInfo.bgColor} ${statusInfo.color}`}>
                        <statusInfo.icon className="w-3 h-3" />
                        <span>{statusInfo.status}</span>
                      </div>
                    </div>
                  </div>

                  {/* Reconnect/Authentication Notice */}
                  {statusInfo.needsReconnect && (
                    <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-4">
                      <div className="flex items-center space-x-2 mb-2">
                        <Key className="w-4 h-4 text-amber-600" />
                        <span className="text-amber-700 text-sm font-medium">
                          Reconnection Required
                        </span>
                      </div>
                      <p className="text-amber-600 text-xs mb-3">
                        Your access token has expired or will expire soon. Reconnect using your stored credentials.
                      </p>
                      <motion.button
                        onClick={() => handleReconnectNow(connection.id)}
                        disabled={reconnectingConnection === connection.id}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        className="w-full bg-gradient-to-r from-amber-500 to-amber-600 text-white py-2 px-3 rounded-lg hover:shadow-3d transition-all flex items-center justify-center space-x-2 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {reconnectingConnection === connection.id ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin" />
                            <span>Reconnecting...</span>
                          </>
                        ) : (
                          <>
                            <RefreshCw className="w-4 h-4" />
                            <span>Reconnect Now</span>
                          </>
                        )}
                      </motion.button>
                    </div>
                  )}

                  {/* Webhook URL */}
                  {connection.webhook_url && (
                    <div className="bg-beige-50 rounded-lg p-3 mb-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-bronze-600">Webhook URL:</span>
                        <motion.button
                          onClick={() => copyWebhookUrl(connection.webhook_url, connection.id)}
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                          className="text-amber-600 hover:text-amber-500"
                        >
                          {copiedWebhook === connection.id ? (
                            <CheckCircle className="w-4 h-4" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </motion.button>
                      </div>
                      <code className="text-xs text-bronze-700 break-all block">
                        {connection.webhook_url.length > 60 
                          ? `${connection.webhook_url.substring(0, 60)}...`
                          : connection.webhook_url
                        }
                      </code>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="space-y-2">
                    {connection.is_authenticated && !statusInfo.needsReconnect && (
                      <div className="grid grid-cols-2 gap-2">
                        <motion.button 
                          onClick={() => syncPositions(connection.id)}
                          disabled={syncingConnection === connection.id}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          className="bg-amber-500 text-white py-2 px-3 rounded-lg hover:bg-amber-600 transition-colors flex items-center justify-center space-x-1 text-sm disabled:opacity-50 shadow-3d"
                        >
                          <RefreshCw className={`w-3 h-3 ${syncingConnection === connection.id ? 'animate-spin' : ''}`} />
                          <span>Sync</span>
                        </motion.button>

                        <motion.button
                          onClick={() => testConnection(connection.id)}
                          disabled={testingConnection === connection.id}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          className="bg-blue-500 text-white py-2 px-3 rounded-lg hover:bg-blue-600 transition-colors flex items-center justify-center space-x-1 text-sm disabled:opacity-50 shadow-3d"
                        >
                          <TestTube className={`w-3 h-3 ${testingConnection === connection.id ? 'animate-pulse' : ''}`} />
                          <span>Test</span>
                        </motion.button>
                      </div>
                    )}

                    <motion.button 
                      onClick={() => handleEditConnection(connection)}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      className="w-full bg-bronze-500 text-white py-2 rounded-lg hover:bg-bronze-600 transition-colors flex items-center justify-center space-x-2 text-sm shadow-3d"
                    >
                      <Edit3 className="w-4 h-4" />
                      <span>Edit Settings</span>
                    </motion.button>
                    
                    {/* Connection Management Buttons */}
                    {connection.is_active ? (
                      <motion.button
                        onClick={() => disconnectBroker(connection.id)}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="w-full bg-red-100 text-red-600 py-2 rounded-lg hover:bg-red-200 transition-colors text-sm border border-red-200"
                      >
                        Disconnect
                      </motion.button>
                    ) : (
                      <div className="space-y-2">
                        <motion.button
                          onClick={() => deleteBrokerConnection(connection.id)}
                          disabled={deletingConnection === connection.id}
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          className="w-full bg-red-500 text-white py-2 rounded-lg hover:bg-red-600 transition-colors flex items-center justify-center space-x-1 text-sm disabled:opacity-50 shadow-3d"
                        >
                          {deletingConnection === connection.id ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                          ) : (
                            <Trash2 className="w-4 h-4" />
                          )}
                          <span>Delete</span>
                        </motion.button>
                      </div>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      )}

      {/* Available Brokers Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        whileHover={{ scale: 1.005 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 border border-beige-200 shadow-3d"
      >
        <h2 className="text-2xl font-bold text-bronze-800 mb-6 flex items-center">
          <Zap className="w-6 h-6 mr-2 text-amber-600" />
          Available Brokers
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {brokers.map((broker, index) => {
            const activeConnections = connections.filter(c => c.broker_name.toLowerCase() === broker.id && c.is_active);
            
            return (
              <motion.div
                key={broker.id}
                initial={{ opacity: 0, y: 30, rotateY: -15 }}
                animate={{ opacity: 1, y: 0, rotateY: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                whileHover={{ 
                  rotateY: 5,
                  scale: 1.02
                }}
                className="group p-6 rounded-2xl border-2 border-beige-200 bg-cream-50 hover:border-amber-300 transition-all duration-500 shadow-3d hover:shadow-3d-hover"
              >
                <div className="text-center">
                  <motion.div 
                    className="text-5xl mb-4 group-hover:scale-110 transition-transform duration-300"
                    whileHover={{ rotate: 180 }}
                    transition={{ duration: 0.6 }}
                  >
                    {broker.logo}
                  </motion.div>
                  <h3 className="font-bold text-bronze-800 mb-2 text-xl group-hover:text-amber-700 transition-colors">
                    {broker.name}
                  </h3>
                  <p className="text-bronze-600 mb-6">
                    {broker.description}
                  </p>
                  
                  <div className="space-y-3 mb-6">
                    {broker.features.map((feature, featureIndex) => (
                      <div key={featureIndex} className="flex items-center space-x-3">
                        <CheckCircle className="w-4 h-4 text-amber-600 flex-shrink-0" />
                        <span className="text-bronze-700 text-sm">{feature}</span>
                      </div>
                    ))}
                  </div>

                  {activeConnections.length > 0 && (
                    <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg">
                      <div className="flex items-center justify-center space-x-2 text-green-700">
                        <CheckCircle className="w-4 h-4" />
                        <span className="text-sm font-medium">
                          {activeConnections.length} Active Connection{activeConnections.length > 1 ? 's' : ''}
                        </span>
                      </div>
                    </div>
                  )}
                  
                  <motion.button 
                    onClick={() => handleConnectClick(broker.id)}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-3 rounded-xl hover:shadow-3d-hover transition-all font-medium shadow-3d"
                  >
                    Connect {broker.name}
                  </motion.button>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* Zerodha Authentication Modal */}
      <AnimatePresence>
        {authenticationStep && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-2xl p-6 max-w-md w-full border border-beige-200 shadow-3d"
            >
              <h3 className="text-xl font-bold text-bronze-800 mb-4">Complete Broker Authentication</h3>
              <p className="text-bronze-600 mb-6">
                Click the button below to open the broker login page. After logging in and authorizing the app, 
                the authentication will be completed automatically.
              </p>
              
              <div className="space-y-4">
                <motion.button
                  onClick={() => handleZerodhaAuth(authenticationStep.connectionId, authenticationStep.loginUrl)}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-3 rounded-xl font-medium flex items-center justify-center space-x-2 shadow-3d"
                >
                  <ExternalLink className="w-4 h-4" />
                  <span>Open Broker Login</span>
                </motion.button>

                <motion.button
                  onClick={() => setAuthenticationStep(null)}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full bg-beige-100 text-bronze-700 py-3 rounded-xl font-medium border border-beige-200"
                >
                  Cancel
                </motion.button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Connection Form */}
      <AnimatePresence>
        {showConnectionForm && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: -20 }}
              className="bg-white rounded-2xl p-6 max-w-md w-full border border-beige-200 max-h-[90vh] overflow-y-auto shadow-3d"
            >
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-bronze-800 flex items-center">
                  <Link className="w-6 h-6 mr-2 text-amber-600" />
                  Connect Broker
                </h2>
                <motion.button
                  onClick={() => {
                    setShowConnectionForm(false);
                    setSelectedBrokerForConnection('');
                    reset();
                  }}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="text-bronze-600 hover:text-bronze-500 text-xl"
                >
                  ✕
                </motion.button>
              </div>
              
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Select Broker
                  </label>
                  <select
                    {...register('brokerName', { required: 'Please select a broker' })}
                    className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                    value={selectedBrokerForConnection || ''}
                    onChange={(e) => {
                      setSelectedBrokerForConnection(e.target.value);
                      setValue('brokerName', e.target.value);
                    }}
                  >
                    <option value="">Choose a broker...</option>
                    {brokers.map(broker => (
                      <option key={broker.id} value={broker.id}>
                        {broker.name}
                      </option>
                    ))}
                  </select>
                  {errors.brokerName && (
                    <p className="mt-1 text-sm text-red-600">{errors.brokerName.message}</p>
                  )}
                </div>

                {selectedBroker && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    className="space-y-6"
                  >
                    <div>
                      <label className="block text-sm font-medium text-bronze-700 mb-2">
                        Connection Name (Optional)
                      </label>
                      <input
                        {...register('connectionName')}
                        type="text"
                        className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                        placeholder="My Trading Account"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-bronze-700 mb-2">
                        API Key
                      </label>
                      <input
                        {...register('apiKey', { required: 'API Key is required' })}
                        type="text"
                        className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                        placeholder="Enter your API key"
                      />
                      {errors.apiKey && (
                        <p className="mt-1 text-sm text-red-600">{errors.apiKey.message}</p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-bronze-700 mb-2">
                        API Secret
                      </label>
                      <div className="relative">
                        <input
                          {...register('apiSecret', { required: 'API Secret is required' })}
                          type={showApiSecret ? 'text' : 'password'}
                          className="w-full px-4 py-3 pr-12 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                          placeholder="Enter your API secret"
                        />
                        <button
                          type="button"
                          onClick={() => setShowApiSecret(!showApiSecret)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                        >
                          {showApiSecret ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                        </button>
                      </div>
                      {errors.apiSecret && (
                        <p className="mt-1 text-sm text-red-600">{errors.apiSecret.message}</p>
                      )}
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-bronze-700 mb-2">
                        User ID
                      </label>
                      <input
                        {...register('userId', { required: 'User ID is required' })}
                        type="text"
                        className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                        placeholder="Enter your user ID"
                      />
                      {errors.userId && (
                        <p className="mt-1 text-sm text-red-600">{errors.userId.message}</p>
                      )}
                    </div>

                    {/* Shoonya-specific fields */}
                    {selectedBroker === 'shoonya' && (
                      <>
                        <div>
                          <label className="block text-sm font-medium text-bronze-700 mb-2">
                            Password
                          </label>
                          <div className="relative">
                            <input
                              {...register('password', { 
                                required: selectedBroker === 'shoonya' ? 'Password is required for Shoonya' : false 
                              })}
                              type={showApiSecret ? 'text' : 'password'}
                              className="w-full px-4 py-3 pr-12 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                              placeholder="Enter your login password"
                            />
                            <button
                              type="button"
                              onClick={() => setShowApiSecret(!showApiSecret)}
                              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                            >
                              {showApiSecret ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                            </button>
                          </div>
                          {errors.password && (
                            <p className="mt-1 text-sm text-red-600">{errors.password.message}</p>
                          )}
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-bronze-700 mb-2">
                            2FA/PIN
                          </label>
                          <input
                            {...register('twoFA', { 
                              required: selectedBroker === 'shoonya' ? '2FA/PIN is required for Shoonya' : false 
                            })}
                            type="text"
                            className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                            placeholder="Enter your 2FA/PIN"
                          />
                          {errors.twoFA && (
                            <p className="mt-1 text-sm text-red-600">{errors.twoFA.message}</p>
                          )}
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-bronze-700 mb-2">
                            Vendor Code
                          </label>
                          <input
                            {...register('vendor', { 
                              required: selectedBroker === 'shoonya' ? 'Vendor code is required for Shoonya' : false 
                            })}
                            type="text"
                            className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                            placeholder="Enter vendor code (e.g., SHOONYA_API)"
                          />
                          {errors.vendor && (
                            <p className="mt-1 text-sm text-red-600">{errors.vendor.message}</p>
                          )}
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-bronze-700 mb-2">
                            App Key
                          </label>
                          <input
                            {...register('appKey', { 
                              required: selectedBroker === 'shoonya' ? 'App key is required for Shoonya' : false 
                            })}
                            type="text"
                            className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                            placeholder="Enter your app key"
                          />
                          {errors.appKey && (
                            <p className="mt-1 text-sm text-red-600">{errors.appKey.message}</p>
                          )}
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-bronze-700 mb-2">
                            IMEI
                          </label>
                          <input
                            {...register('imei', { 
                              required: selectedBroker === 'shoonya' ? 'IMEI is required for Shoonya' : false 
                            })}
                            type="text"
                            className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                            placeholder="Enter device IMEI"
                          />
                          {errors.imei && (
                            <p className="mt-1 text-sm text-red-600">{errors.imei.message}</p>
                          )}
                        </div>

                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <div className="flex items-center space-x-2 mb-2">
                            <AlertCircle className="w-4 h-4 text-blue-600" />
                            <span className="text-blue-700 text-sm font-medium">Shoonya Setup Guide</span>
                          </div>
                          <ul className="text-blue-600 text-xs space-y-1">
                            <li>• Get API credentials from Shoonya developer portal</li>
                            <li>• Vendor code is usually provided by Shoonya</li>
                            <li>• App key is generated when you create an API app</li>
                            <li>• IMEI can be any unique device identifier</li>
                          </ul>
                        </div>
                      </>
                    )}

                    <div className="flex space-x-4">
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        type="submit"
                        disabled={isSubmitting}
                        className="flex-1 bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-3 rounded-xl font-medium hover:shadow-3d-hover transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-3d"
                      >
                        <Link className="w-4 h-4" />
                        <span>{isSubmitting ? 'Connecting...' : 'Connect Broker'}</span>
                      </motion.button>

                      <motion.button
                        type="button"
                        onClick={() => {
                          setShowConnectionForm(false);
                          setSelectedBrokerForConnection('');
                          reset();
                        }}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className="px-6 py-3 bg-beige-100 text-bronze-700 rounded-xl font-medium hover:bg-beige-200 transition-colors border border-beige-200"
                      >
                        Cancel
                      </motion.button>
                    </div>
                  </motion.div>
                )}
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Edit Connection Form */}
      <AnimatePresence>
        {showEditForm && editingConnection && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: -20 }}
              className="bg-white rounded-2xl p-6 max-w-md w-full border border-beige-200 max-h-[90vh] overflow-y-auto shadow-3d"
            >
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-bronze-800 flex items-center">
                  <Edit3 className="w-6 h-6 mr-2 text-amber-600" />
                  Edit {editingConnection.broker_name.charAt(0).toUpperCase() + editingConnection.broker_name.slice(1)} Settings
                </h2>
                <motion.button
                  onClick={() => {
                    setShowEditForm(false);
                    setEditingConnection(null);
                    reset();
                  }}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="text-bronze-600 hover:text-bronze-500 text-xl"
                >
                  ✕
                </motion.button>
              </div>

              <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6">
                <div className="flex items-center space-x-2 mb-2">
                  <AlertCircle className="w-4 h-4 text-amber-600" />
                  <span className="text-amber-700 text-sm font-medium">Security Notice</span>
                </div>
                <p className="text-amber-600 text-xs">
                  For security reasons, existing API credentials are not displayed. Enter new credentials to update your connection.
                </p>
              </div>
              
              <form onSubmit={handleSubmit(onEditSubmit)} className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    Connection Name
                  </label>
                  <input
                    {...register('connectionName')}
                    type="text"
                    className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                    placeholder="My Trading Account"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    API Key
                  </label>
                  <input
                    {...register('apiKey')}
                    type="text"
                    className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                    placeholder="Enter new API key"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    API Secret
                  </label>
                  <div className="relative">
                    <input
                      {...register('apiSecret')}
                      type={showApiSecret ? 'text' : 'password'}
                      className="w-full px-4 py-3 pr-12 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                      placeholder="Enter new API secret"
                    />
                    <button
                      type="button"
                      onClick={() => setShowApiSecret(!showApiSecret)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-bronze-400 hover:text-bronze-600 transition-colors"
                    >
                      {showApiSecret ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-bronze-700 mb-2">
                    User ID
                  </label>
                  <input
                    {...register('userId', { required: 'User ID is required' })}
                    type="text"
                    className="w-full px-4 py-3 bg-cream-50 border border-beige-200 rounded-xl text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent backdrop-blur-sm"
                    placeholder="Enter your user ID"
                  />
                  {errors.userId && (
                    <p className="mt-1 text-sm text-red-600">{errors.userId.message}</p>
                  )}
                </div>

                <div className="flex space-x-4">
                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    type="submit"
                    disabled={isSubmitting}
                    className="flex-1 bg-gradient-to-r from-amber-500 to-bronze-600 text-white py-3 rounded-xl font-medium hover:shadow-3d-hover transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-3d"
                  >
                    <Settings className="w-4 h-4" />
                    <span>{isSubmitting ? 'Updating...' : 'Update Connection'}</span>
                  </motion.button>

                  <motion.button
                    type="button"
                    onClick={() => {
                      setShowEditForm(false);
                      setEditingConnection(null);
                      reset();
                    }}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    className="px-6 py-3 bg-beige-100 text-bronze-700 rounded-xl font-medium hover:bg-beige-200 transition-colors border border-beige-200"
                  >
                    Cancel
                  </motion.button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default BrokerConnection;