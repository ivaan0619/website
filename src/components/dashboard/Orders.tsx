import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, Filter, Download, Calendar, TrendingUp, TrendingDown, 
  RefreshCw, Eye, ExternalLink, Clock, CheckCircle, XCircle,
  AlertCircle, Loader, MoreVertical, Edit3, Play, Square, Activity
} from 'lucide-react';
import { format } from 'date-fns';
import { ordersAPI, brokerAPI } from '../../services/api';
import toast from 'react-hot-toast';

interface Order {
  id: number;
  symbol: string;
  transaction_type: string;
  quantity: number;
  order_type: string;
  price: number;
  executed_price: number;
  executed_quantity: number;
  status: string;
  created_at: string;
  updated_at: string;
  pnl: number;
  broker_name: string;
  broker_order_id: string;
  webhook_data: any;
  status_message: any;
  broker_data?: any;
  polling_started?: boolean;
  is_final_status?: boolean;
}

const Orders: React.FC = () => {
  const [orders, setOrders] = useState<Order[]>([]);
  const [brokerConnections, setBrokerConnections] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [brokerFilter, setBrokerFilter] = useState('all');
  const [selectedOrder, setSelectedOrder] = useState<Order | null>(null);
  const [showOrderDetails, setShowOrderDetails] = useState(false);
  const [syncingBroker, setSyncingBroker] = useState<number | null>(null);
  const [pollingOrders, setPollingOrders] = useState<Set<number>>(new Set());
  const [orderPollingStatus, setOrderPollingStatus] = useState<{[key: number]: boolean}>({});
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  });

  useEffect(() => {
    fetchInitialData();
  }, []);

  useEffect(() => {
    fetchOrders();
  }, [pagination.page, statusFilter, typeFilter, brokerFilter, searchTerm]);

  // Auto-refresh orders every 30 seconds when there are active orders
  useEffect(() => {
    const interval = setInterval(() => {
      if (orders.some(order => !isFinalStatus(order.status))) {
        fetchOrders(true); // Silent refresh
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [orders]);

  useEffect(() => {
    const pollingInterval = setInterval(() => {
      if (pollingOrders.size > 0) {
        fetchOrders(true); // Silent refresh to update statuses
      }
    }, 5000); // Poll every 5 seconds when there are active polling orders

    return () => clearInterval(pollingInterval);
  }, [pollingOrders]);

  const fetchInitialData = async () => {
    try {
      const [ordersResponse, connectionsResponse] = await Promise.all([
        ordersAPI.getOrders({ 
          page: pagination.page, 
          limit: pagination.limit,
          status: statusFilter !== 'all' ? statusFilter : undefined,
          symbol: searchTerm || undefined
        }),
        brokerAPI.getConnections()
      ]);

      setOrders(ordersResponse.data.orders);
      setPagination(ordersResponse.data.pagination);
      setBrokerConnections(connectionsResponse.data.connections);
    } catch (error) {
      console.error('Failed to fetch initial data:', error);
      toast.error('Failed to fetch orders');
    } finally {
      setLoading(false);
    }
  };

  const fetchOrders = async (silent = false) => {
    if (loading && !silent) return; // Don't fetch if initial load is in progress

    try {
      if (!silent) setRefreshing(true);

      const params: any = {
        page: pagination.page,
        limit: pagination.limit
      };

      if (statusFilter !== 'all') params.status = statusFilter;
      if (typeFilter !== 'all') params.transaction_type = typeFilter;
      if (brokerFilter !== 'all') params.broker_connection_id = brokerFilter;
      if (searchTerm) params.symbol = searchTerm;

      const response = await ordersAPI.getOrders(params);
      setOrders(response.data.orders);
      setPagination(response.data.pagination);
    } catch (error) {
      console.error('Failed to fetch orders:', error);
      if (!silent) toast.error('Failed to fetch orders');
    } finally {
      if (!silent) setRefreshing(false);
    }
  };

  const refreshOrders = async (syncFromBroker = false) => {
    setRefreshing(true);
    try {
      if (syncFromBroker && brokerFilter !== 'all') {
        // Sync from specific broker
        setSyncingBroker(parseInt(brokerFilter));
        await ordersAPI.syncOrders(brokerFilter);
        toast.success('Orders synced from broker successfully');
      }

      // Refresh orders list
      await fetchOrders();
    } catch (error) {
      console.error('Failed to refresh orders:', error);
      toast.error('Failed to refresh orders');
    } finally {
      setRefreshing(false);
      setSyncingBroker(null);
    }
  };

  const viewOrderDetails = async (order: Order) => {
    try {
      setSelectedOrder(order);
      setShowOrderDetails(true);

      // Fetch detailed order information with broker sync and start polling if needed
      const response = await ordersAPI.getOrderDetails(order.id, { 
        sync: true, 
        startPolling: !isFinalStatus(order.status) 
      });
      
      const updatedOrder = response.data.order;
      setSelectedOrder(updatedOrder);
      
      // Update polling status if polling was started
      if (updatedOrder.polling_started) {
        setOrderPollingStatus(prev => ({
          ...prev,
          [order.id]: true
        }));
      }
      
    } catch (error) {
      console.error('Failed to fetch order details:', error);
      toast.error('Failed to fetch order details');
    }
  };

  const startOrderPolling = async (orderId: number) => {
    try {
      setPollingOrders(prev => new Set([...prev, orderId]));
      
      const response = await ordersAPI.startOrderPolling(orderId);
      
      setOrderPollingStatus(prev => ({
        ...prev,
        [orderId]: true
      }));
      
      toast.success('Real-time monitoring started for order');
      
    } catch (error: any) {
      console.error('Failed to start order polling:', error);
      toast.error(error.response?.data?.error || 'Failed to start real-time monitoring');
      setPollingOrders(prev => {
        const newSet = new Set(prev);
        newSet.delete(orderId);
        return newSet;
      });
    }
  };

  const stopOrderPolling = async (orderId: number) => {
    try {
      await ordersAPI.stopOrderPolling(orderId);
      
      setPollingOrders(prev => {
        const newSet = new Set(prev);
        newSet.delete(orderId);
        return newSet;
      });
      
      setOrderPollingStatus(prev => ({
        ...prev,
        [orderId]: false
      }));
      
      toast.success('Real-time monitoring stopped for order');
      
    } catch (error: any) {
      console.error('Failed to stop order polling:', error);
      toast.error(error.response?.data?.error || 'Failed to stop real-time monitoring');
    }
  };

  const isFinalStatus = (status: string) => {
    const finalStatuses = ['COMPLETE', 'CANCELLED', 'REJECTED'];
    return finalStatuses.includes(status?.toUpperCase());
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'complete':
      case 'executed':
        return 'bg-olive-800/30 text-olive-300';
      case 'open':
      case 'pending':
        return 'bg-yellow-800/30 text-yellow-300';
      case 'cancelled':
        return 'bg-dark-700/30 text-olive-200';
      case 'rejected':
      case 'failed':
        return 'bg-red-800/30 text-red-300';
      default:
        return 'bg-dark-700/30 text-olive-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'complete':
      case 'executed':
        return <CheckCircle className="w-4 h-4" />;
      case 'open':
      case 'pending':
        return <Clock className="w-4 h-4" />;
      case 'cancelled':
        return <XCircle className="w-4 h-4" />;
      case 'rejected':
      case 'failed':
        return <AlertCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getPnLColor = (pnl: number) => {
    if (pnl > 0) return 'text-olive-400';
    if (pnl < 0) return 'text-red-400';
    return 'text-olive-200';
  };

  const filteredOrders = orders.filter(order => {
    const matchesSearch = order.symbol.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         order.id.toString().includes(searchTerm);
    return matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-olive-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white">Order Management</h1>
          <p className="text-olive-200/70 mt-1">Track and manage all your automated and manual trades with real-time updates</p>
        </div>
        <div className="flex items-center space-x-3 mt-4 sm:mt-0">
          <motion.button 
            onClick={() => refreshOrders(false)}
            disabled={refreshing}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 bg-olive-600 text-white px-4 py-2 rounded-lg hover:bg-olive-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </motion.button>

          {brokerFilter !== 'all' && (
            <motion.button 
              onClick={() => refreshOrders(true)}
              disabled={syncingBroker !== null}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${syncingBroker ? 'animate-spin' : ''}`} />
              <span>Sync from Broker</span>
            </motion.button>
          )}

          <motion.button 
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 bg-dark-700 text-olive-200 px-4 py-2 rounded-lg hover:bg-dark-600 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Enhanced Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
      >
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-olive-400/50" />
            <input
              type="text"
              placeholder="Search orders..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-dark-800/50 border border-olive-500/20 rounded-lg text-white placeholder-olive-300/50 focus:ring-2 focus:ring-olive-500 focus:border-transparent"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 bg-dark-800/50 border border-olive-500/20 rounded-lg text-white focus:ring-2 focus:ring-olive-500 focus:border-transparent"
          >
            <option value="all">All Status</option>
            <option value="COMPLETE">Complete</option>
            <option value="OPEN">Open</option>
            <option value="PENDING">Pending</option>
            <option value="CANCELLED">Cancelled</option>
            <option value="REJECTED">Rejected</option>
          </select>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-4 py-2 bg-dark-800/50 border border-olive-500/20 rounded-lg text-white focus:ring-2 focus:ring-olive-500 focus:border-transparent"
          >
            <option value="all">All Types</option>
            <option value="BUY">Buy</option>
            <option value="SELL">Sell</option>
          </select>

          <select
            value={brokerFilter}
            onChange={(e) => setBrokerFilter(e.target.value)}
            className="px-4 py-2 bg-dark-800/50 border border-olive-500/20 rounded-lg text-white focus:ring-2 focus:ring-olive-500 focus:border-transparent"
          >
            <option value="all">All Brokers</option>
            {brokerConnections.map(broker => (
              <option key={broker.id} value={broker.id}>
                {broker.broker_name.charAt(0).toUpperCase() + broker.broker_name.slice(1)}
              </option>
            ))}
          </select>

          <div className="flex items-center space-x-2">
            <Calendar className="w-5 h-5 text-olive-400/50" />
            <input
              type="date"
              className="px-4 py-2 bg-dark-800/50 border border-olive-500/20 rounded-lg text-white focus:ring-2 focus:ring-olive-500 focus:border-transparent"
            />
          </div>
        </div>
      </motion.div>

      {/* Enhanced Orders Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-dark-800/50 backdrop-blur-xl rounded-2xl shadow-xl border border-olive-500/20 overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-olive-800/20">
              <tr>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Order ID</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Symbol</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Type</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Quantity</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Price</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Executed</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">P&L</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Status</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Broker</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Time</th>
                <th className="text-left py-4 px-6 font-semibold text-olive-200">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredOrders.map((order, index) => (
                <motion.tr
                  key={order.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="border-b border-olive-500/10 hover:bg-olive-800/10 transition-colors"
                >
                  <td className="py-4 px-6">
                    <div className="flex flex-col">
                      <span className="font-medium text-white">#{order.id}</span>
                      {order.broker_order_id && (
                        <span className="text-xs text-olive-200/70">{order.broker_order_id}</span>
                      )}
                      {orderPollingStatus[order.id] && (
                        <div className="flex items-center space-x-1 mt-1">
                          <Activity className="w-3 h-3 text-green-400 animate-pulse" />
                          <span className="text-xs text-green-400">Live</span>
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="py-4 px-6 font-medium text-white">{order.symbol}</td>
                  <td className="py-4 px-6">
                    <div className="flex items-center space-x-2">
                      {order.transaction_type === 'BUY' ? (
                        <TrendingUp className="w-4 h-4 text-olive-400" />
                      ) : (
                        <TrendingDown className="w-4 h-4 text-red-400" />
                      )}
                      <span className={`font-medium ${
                        order.transaction_type === 'BUY' ? 'text-olive-400' : 'text-red-400'
                      }`}>
                        {order.transaction_type}
                      </span>
                    </div>
                  </td>
                  <td className="py-4 px-6">
                    <div className="flex flex-col">
                      <span className="text-olive-200">{order.quantity}</span>
                      {order.executed_quantity > 0 && order.executed_quantity !== order.quantity && (
                        <span className="text-xs text-olive-200/70">
                          Filled: {order.executed_quantity}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-4 px-6 text-olive-200">
                    ₹{order.price?.toFixed(2) || 'Market'}
                  </td>
                  <td className="py-4 px-6 text-olive-200">
                    {order.executed_price ? `₹${order.executed_price.toFixed(2)}` : '-'}
                  </td>
                  <td className="py-4 px-6">
                    <span className={`font-medium ${getPnLColor(order.pnl)}`}>
                      {order.pnl > 0 ? '+' : ''}₹{order.pnl?.toFixed(2) || '0.00'}
                    </span>
                  </td>
                  <td className="py-4 px-6">
                    <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
                      {getStatusIcon(order.status)}
                      <span>{order.status}</span>
                    </div>
                  </td>
                  <td className="py-4 px-6">
                    <span className="text-olive-200 capitalize">
                      {order.broker_name || 'Unknown'}
                    </span>
                  </td>
                  <td className="py-4 px-6 text-olive-200">
                    <div className="flex flex-col">
                      <span>{format(new Date(order.created_at), 'MMM dd, HH:mm')}</span>
                      {order.updated_at !== order.created_at && (
                        <span className="text-xs text-olive-200/70">
                          Updated: {format(new Date(order.updated_at), 'HH:mm')}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-4 px-6">
                    <div className="flex items-center space-x-2">
                      <motion.button
                        onClick={() => viewOrderDetails(order)}
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                        className="text-olive-400 hover:text-olive-300 transition-colors"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </motion.button>
                      
                      {/* Real-time monitoring controls */}
                      {order.broker_order_id && !isFinalStatus(order.status) && (
                        <>
                          {orderPollingStatus[order.id] ? (
                            <motion.button
                              onClick={() => stopOrderPolling(order.id)}
                              whileHover={{ scale: 1.1 }}
                              whileTap={{ scale: 0.9 }}
                              className="text-red-400 hover:text-red-300 transition-colors"
                              title="Stop Real-time Monitoring"
                            >
                              <Square className="w-4 h-4" />
                            </motion.button>
                          ) : (
                            <motion.button
                              onClick={() => startOrderPolling(order.id)}
                              disabled={pollingOrders.has(order.id)}
                              whileHover={{ scale: 1.1 }}
                              whileTap={{ scale: 0.9 }}
                              className="text-green-400 hover:text-green-300 transition-colors disabled:opacity-50"
                              title="Start Real-time Monitoring"
                            >
                              {pollingOrders.has(order.id) ? (
                                <Loader className="w-4 h-4 animate-spin" />
                              ) : (
                                <Play className="w-4 h-4" />
                              )}
                            </motion.button>
                          )}
                        </>
                      )}
                      
                      {order.broker_order_id && (
                        <motion.button
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                          title="View on Broker"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </motion.button>
                      )}
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredOrders.length === 0 && (
          <div className="text-center py-12">
            <div className="text-olive-400 text-lg mb-2">No orders found</div>
            <p className="text-olive-200/70">Try adjusting your search criteria or sync from your broker</p>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t border-olive-500/10">
            <div className="text-sm text-olive-200/70">
              Showing {((pagination.page - 1) * pagination.limit) + 1} to {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total} orders
            </div>
            <div className="flex items-center space-x-2">
              <motion.button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                disabled={pagination.page === 1}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-3 py-1 bg-dark-700 text-olive-200 rounded disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </motion.button>
              
              <span className="text-olive-200">
                Page {pagination.page} of {pagination.pages}
              </span>
              
              <motion.button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.min(prev.pages, prev.page + 1) }))}
                disabled={pagination.page === pagination.pages}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-3 py-1 bg-dark-700 text-olive-200 rounded disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </motion.button>
            </div>
          </div>
        )}
      </motion.div>

      {/* Order Details Modal */}
      <AnimatePresence>
        {showOrderDetails && selectedOrder && (
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
              className="bg-dark-800 rounded-2xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-olive-500/20"
            >
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <h3 className="text-xl font-bold text-white">Order Details</h3>
                  {selectedOrder.polling_started && (
                    <div className="flex items-center space-x-1 px-2 py-1 bg-green-800/20 rounded-full">
                      <Activity className="w-3 h-3 text-green-400 animate-pulse" />
                      <span className="text-xs text-green-400">Live Monitoring</span>
                    </div>
                  )}
                </div>
                <motion.button
                  onClick={() => setShowOrderDetails(false)}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="text-olive-400 hover:text-olive-300 text-xl"
                >
                  ✕
                </motion.button>
              </div>

              <div className="space-y-6">
                {/* Order Summary */}
                <div className="bg-dark-900/50 rounded-xl p-4">
                  <h4 className="font-semibold text-olive-300 mb-3">Order Summary</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-olive-200/70 text-sm">Order ID:</span>
                      <p className="text-white font-medium">#{selectedOrder.id}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Broker Order ID:</span>
                      <p className="text-white font-medium">{selectedOrder.broker_order_id || 'N/A'}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Symbol:</span>
                      <p className="text-white font-medium">{selectedOrder.symbol}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Type:</span>
                      <p className={`font-medium ${selectedOrder.transaction_type === 'BUY' ? 'text-olive-400' : 'text-red-400'}`}>
                        {selectedOrder.transaction_type}
                      </p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Quantity:</span>
                      <p className="text-white font-medium">{selectedOrder.quantity}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Executed:</span>
                      <p className="text-white font-medium">{selectedOrder.executed_quantity || 0}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Order Price:</span>
                      <p className="text-white font-medium">₹{selectedOrder.price?.toFixed(2) || 'Market'}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Executed Price:</span>
                      <p className="text-white font-medium">
                        {selectedOrder.executed_price ? `₹${selectedOrder.executed_price.toFixed(2)}` : 'N/A'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Status and Timing */}
                <div className="bg-dark-900/50 rounded-xl p-4">
                  <h4 className="font-semibold text-olive-300 mb-3">Status & Timing</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-olive-200/70 text-sm">Status:</span>
                      <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium mt-1 ${getStatusColor(selectedOrder.status)}`}>
                        {getStatusIcon(selectedOrder.status)}
                        <span>{selectedOrder.status}</span>
                      </div>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Broker:</span>
                      <p className="text-white font-medium capitalize">{selectedOrder.broker_name}</p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Created:</span>
                      <p className="text-white font-medium">
                        {format(new Date(selectedOrder.created_at), 'MMM dd, yyyy HH:mm:ss')}
                      </p>
                    </div>
                    <div>
                      <span className="text-olive-200/70 text-sm">Updated:</span>
                      <p className="text-white font-medium">
                        {format(new Date(selectedOrder.updated_at), 'MMM dd, yyyy HH:mm:ss')}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Real-time Monitoring Controls */}
                {selectedOrder.broker_order_id && !selectedOrder.is_final_status && (
                  <div className="bg-dark-900/50 rounded-xl p-4">
                    <h4 className="font-semibold text-olive-300 mb-3">Real-time Monitoring</h4>
                    <div className="flex items-center space-x-4">
                      {orderPollingStatus[selectedOrder.id] ? (
                        <motion.button
                          onClick={() => stopOrderPolling(selectedOrder.id)}
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          className="flex items-center space-x-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
                        >
                          <Square className="w-4 h-4" />
                          <span>Stop Monitoring</span>
                        </motion.button>
                      ) : (
                        <motion.button
                          onClick={() => startOrderPolling(selectedOrder.id)}
                          disabled={pollingOrders.has(selectedOrder.id)}
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          className="flex items-center space-x-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50"
                        >
                          {pollingOrders.has(selectedOrder.id) ? (
                            <>
                              <Loader className="w-4 h-4 animate-spin" />
                              <span>Starting...</span>
                            </>
                          ) : (
                            <>
                              <Play className="w-4 h-4" />
                              <span>Start Monitoring</span>
                            </>
                          )}
                        </motion.button>
                      )}
                      <p className="text-olive-200/70 text-sm">
                        Monitor order status changes in real-time from your broker
                      </p>
                    </div>
                  </div>
                )}

                {/* Webhook Data */}
                {selectedOrder.webhook_data && (
                  <div className="bg-dark-900/50 rounded-xl p-4">
                    <h4 className="font-semibold text-olive-300 mb-3">TradingView Signal</h4>
                    <pre className="text-xs text-olive-200 bg-dark-800/50 p-3 rounded-lg overflow-x-auto">
                      {JSON.stringify(selectedOrder.webhook_data, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Broker Response */}
                {selectedOrder.status_message && (
                  <div className="bg-dark-900/50 rounded-xl p-4">
                    <h4 className="font-semibold text-olive-300 mb-3">Broker Response</h4>
                    <pre className="text-xs text-olive-200 bg-dark-800/50 p-3 rounded-lg overflow-x-auto">
                      {typeof selectedOrder.status_message === 'string' 
                        ? selectedOrder.status_message 
                        : JSON.stringify(selectedOrder.status_message, null, 2)
                      }
                    </pre>
                  </div>
                )}

                {/* Live Broker Data */}
                {selectedOrder.broker_data && (
                  <div className="bg-dark-900/50 rounded-xl p-4">
                    <h4 className="font-semibold text-olive-300 mb-3">Live Broker Data</h4>
                    <pre className="text-xs text-olive-200 bg-dark-800/50 p-3 rounded-lg overflow-x-auto">
                      {JSON.stringify(selectedOrder.broker_data, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Orders;