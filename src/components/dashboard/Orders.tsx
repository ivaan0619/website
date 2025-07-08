import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, Filter, Download, Calendar, TrendingUp, TrendingDown, 
  RefreshCw, Eye, ExternalLink, Clock, CheckCircle, XCircle,
  AlertCircle, Loader, MoreVertical, Edit3, Play, Square, Activity,
  Zap, WifiOff, Wifi
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
  exchange?: string;
  product?: string;
  validity?: string;
  trigger_price?: number;
  disclosed_quantity?: number;
  average_price?: number;
  filled_quantity?: number;
  pending_quantity?: number;
  cancelled_quantity?: number;
  order_timestamp?: string;
  exchange_timestamp?: string;
  exchange_order_id?: string;
  parent_order_id?: string;
  status_message_raw?: string;
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
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [openOrdersPolling, setOpenOrdersPolling] = useState<Set<number>>(new Set());
  const [orderStatusUpdates, setOrderStatusUpdates] = useState<{[key: number]: any}>({});
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  });

  useEffect(() => {
    fetchInitialData();
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  useEffect(() => {
    fetchOrders();
  }, [pagination.page, statusFilter, typeFilter, brokerFilter, searchTerm]);

  // Auto-refresh for open orders
  useEffect(() => {
    if (autoRefreshEnabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
    return () => stopAutoRefresh();
  }, [autoRefreshEnabled, orders]);

  const startAutoRefresh = () => {
    stopAutoRefresh();
    
    const openOrders = orders.filter(order => 
      order.status.toUpperCase() === 'OPEN' && order.broker_order_id
    );
    
    if (openOrders.length > 0) {
      intervalRef.current = setInterval(() => {
        refreshOpenOrdersStatus();
      }, 5000); // Check every 5 seconds
    }
  };

  const stopAutoRefresh = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  const refreshOpenOrdersStatus = async () => {
    const openOrders = orders.filter(order => 
      order.status.toUpperCase() === 'OPEN' && order.broker_order_id
    );

    for (const order of openOrders) {
      try {
        const response = await ordersAPI.getOrderDetails(order.id, { sync: true });
        const updatedOrder = response.data.order;
        
        // Update order in the list if status changed
        if (updatedOrder.status !== order.status) {
          setOrders(prevOrders => 
            prevOrders.map(o => 
              o.id === order.id ? { ...o, ...updatedOrder } : o
            )
          );
          
          // Show notification for status change
          toast.success(`Order ${order.symbol} status updated to ${updatedOrder.status}`);
        }
        
        // Update status tracking
        setOrderStatusUpdates(prev => ({
          ...prev,
          [order.id]: {
            ...updatedOrder,
            lastUpdated: new Date().toISOString()
          }
        }));
        
      } catch (error) {
        console.error(`Failed to refresh status for order ${order.id}:`, error);
      }
    }
  };

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
    if (loading && !silent) return;

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
        setSyncingBroker(parseInt(brokerFilter));
        await ordersAPI.syncOrders(brokerFilter);
        toast.success('Orders synced from broker successfully');
      }
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

      // Fetch detailed order information with broker sync
      const response = await ordersAPI.getOrderDetails(order.id, { sync: true });
      const updatedOrder = response.data.order;
      setSelectedOrder(updatedOrder);
      
    } catch (error) {
      console.error('Failed to fetch order details:', error);
      toast.error('Failed to fetch order details');
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
        return 'bg-green-100 text-green-800 border-green-200';
      case 'open':
      case 'pending':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'cancelled':
        return 'bg-gray-100 text-gray-800 border-gray-200';
      case 'rejected':
      case 'failed':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
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
    if (pnl > 0) return 'text-green-600';
    if (pnl < 0) return 'text-red-600';
    return 'text-gray-600';
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  };

  const filteredOrders = orders.filter(order => {
    const matchesSearch = order.symbol.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         order.id.toString().includes(searchTerm);
    return matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500"></div>
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
          <h1 className="text-2xl md:text-3xl font-bold text-bronze-800">Order Management</h1>
          <p className="text-bronze-600 mt-1">Track and manage all your automated and manual trades with real-time updates</p>
        </div>
        <div className="flex items-center space-x-3 mt-4 sm:mt-0">
          {/* Auto-refresh toggle */}
          <motion.button
            onClick={() => setAutoRefreshEnabled(!autoRefreshEnabled)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              autoRefreshEnabled
                ? 'bg-green-600 text-white hover:bg-green-700'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            {autoRefreshEnabled ? (
              <>
                <Wifi className="w-4 h-4 animate-pulse" />
                <span>Live Updates</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4" />
                <span>Manual</span>
              </>
            )}
          </motion.button>

          <motion.button 
            onClick={() => refreshOrders(false)}
            disabled={refreshing}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 bg-amber-600 text-white px-4 py-2 rounded-lg hover:bg-amber-700 transition-colors disabled:opacity-50"
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
            className="flex items-center space-x-2 bg-bronze-600 text-white px-4 py-2 rounded-lg hover:bg-bronze-700 transition-colors"
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
        className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 shadow-3d border border-beige-200"
      >
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-bronze-400" />
            <input
              type="text"
              placeholder="Search orders..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 placeholder-bronze-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
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
            className="px-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
          >
            <option value="all">All Types</option>
            <option value="BUY">Buy</option>
            <option value="SELL">Sell</option>
          </select>

          <select
            value={brokerFilter}
            onChange={(e) => setBrokerFilter(e.target.value)}
            className="px-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
          >
            <option value="all">All Brokers</option>
            {brokerConnections.map(broker => (
              <option key={broker.id} value={broker.id}>
                {broker.broker_name.charAt(0).toUpperCase() + broker.broker_name.slice(1)}
              </option>
            ))}
          </select>

          <div className="flex items-center space-x-2">
            <Calendar className="w-5 h-5 text-bronze-400" />
            <input
              type="date"
              className="px-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
            />
          </div>
        </div>
      </motion.div>

      {/* Enhanced Orders Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-3d border border-beige-200 overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-amber-50">
              <tr>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Order ID</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Symbol</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Type</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Quantity</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Price</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Executed</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">P&L</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Status</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Broker</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Time</th>
                <th className="text-left py-4 px-6 font-semibold text-bronze-800">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredOrders.map((order, index) => {
                const isOpen = order.status.toUpperCase() === 'OPEN';
                const hasStatusUpdate = orderStatusUpdates[order.id];
                
                return (
                  <motion.tr
                    key={order.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className={`border-b border-beige-100 hover:bg-amber-50/50 transition-colors ${
                      isOpen ? 'bg-blue-50/30' : ''
                    }`}
                  >
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="font-medium text-bronze-800">#{order.id}</span>
                        {order.broker_order_id && (
                          <span className="text-xs text-bronze-600">{order.broker_order_id}</span>
                        )}
                        {isOpen && autoRefreshEnabled && (
                          <div className="flex items-center space-x-1 mt-1">
                            <Activity className="w-3 h-3 text-blue-500 animate-pulse" />
                            <span className="text-xs text-blue-500">Monitoring</span>
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="font-medium text-bronze-800">{order.symbol}</span>
                        {order.exchange && (
                          <span className="text-xs text-bronze-600">{order.exchange}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center space-x-2">
                        {order.transaction_type === 'BUY' ? (
                          <TrendingUp className="w-4 h-4 text-green-600" />
                        ) : (
                          <TrendingDown className="w-4 h-4 text-red-600" />
                        )}
                        <span className={`font-medium ${
                          order.transaction_type === 'BUY' ? 'text-green-600' : 'text-red-600'
                        }`}>
                          {order.transaction_type}
                        </span>
                      </div>
                      <div className="text-xs text-bronze-600 mt-1">
                        {order.order_type} • {order.product || 'MIS'}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="text-bronze-800">{order.quantity}</span>
                        {order.executed_quantity > 0 && order.executed_quantity !== order.quantity && (
                          <span className="text-xs text-bronze-600">
                            Filled: {order.executed_quantity}
                          </span>
                        )}
                        {order.pending_quantity && order.pending_quantity > 0 && (
                          <span className="text-xs text-amber-600">
                            Pending: {order.pending_quantity}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="text-bronze-800">
                          {order.price ? formatCurrency(order.price) : 'Market'}
                        </span>
                        {order.trigger_price && (
                          <span className="text-xs text-bronze-600">
                            Trigger: {formatCurrency(order.trigger_price)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="text-bronze-800">
                          {order.executed_price ? formatCurrency(order.executed_price) : '-'}
                        </span>
                        {order.average_price && order.average_price !== order.executed_price && (
                          <span className="text-xs text-bronze-600">
                            Avg: {formatCurrency(order.average_price)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`font-medium ${getPnLColor(order.pnl)}`}>
                        {order.pnl > 0 ? '+' : ''}{formatCurrency(order.pnl || 0)}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(order.status)}`}>
                        {getStatusIcon(order.status)}
                        <span>{order.status}</span>
                        {hasStatusUpdate && (
                          <Zap className="w-3 h-3 text-blue-500 animate-pulse" />
                        )}
                      </div>
                      {hasStatusUpdate && (
                        <div className="text-xs text-blue-600 mt-1">
                          Updated: {format(new Date(hasStatusUpdate.lastUpdated), 'HH:mm:ss')}
                        </div>
                      )}
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-bronze-800 capitalize">
                        {order.broker_name || 'Unknown'}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex flex-col">
                        <span className="text-bronze-800">
                          {format(new Date(order.created_at), 'MMM dd, HH:mm')}
                        </span>
                        {order.updated_at !== order.created_at && (
                          <span className="text-xs text-bronze-600">
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
                          className="text-amber-600 hover:text-amber-700 transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </motion.button>
                        
                        {order.broker_order_id && (
                          <motion.button
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            className="text-blue-600 hover:text-blue-700 transition-colors"
                            title="View on Broker"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </motion.button>
                        )}
                      </div>
                    </td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {filteredOrders.length === 0 && (
          <div className="text-center py-12">
            <div className="text-bronze-600 text-lg mb-2">No orders found</div>
            <p className="text-bronze-500">Try adjusting your search criteria or sync from your broker</p>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t border-beige-200">
            <div className="text-sm text-bronze-600">
              Showing {((pagination.page - 1) * pagination.limit) + 1} to {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total} orders
            </div>
            <div className="flex items-center space-x-2">
              <motion.button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                disabled={pagination.page === 1}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-3 py-1 bg-amber-100 text-bronze-800 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-amber-200 transition-colors"
              >
                Previous
              </motion.button>
              
              <span className="text-bronze-800">
                Page {pagination.page} of {pagination.pages}
              </span>
              
              <motion.button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.min(prev.pages, prev.page + 1) }))}
                disabled={pagination.page === pagination.pages}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-3 py-1 bg-amber-100 text-bronze-800 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-amber-200 transition-colors"
              >
                Next
              </motion.button>
            </div>
          </div>
        )}
      </motion.div>

      {/* Enhanced Order Details Modal */}
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
              className="bg-white rounded-2xl p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-beige-200 shadow-3d"
            >
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <h3 className="text-2xl font-bold text-bronze-800">Order Details</h3>
                  <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium border ${getStatusColor(selectedOrder.status)}`}>
                    {getStatusIcon(selectedOrder.status)}
                    <span>{selectedOrder.status}</span>
                  </div>
                </div>
                <motion.button
                  onClick={() => setShowOrderDetails(false)}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  className="text-bronze-600 hover:text-bronze-500 text-xl"
                >
                  ✕
                </motion.button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Order Information */}
                <div className="space-y-6">
                  <div className="bg-amber-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">Order Information</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <span className="text-bronze-600 text-sm">Order ID:</span>
                          <p className="text-bronze-800 font-medium">#{selectedOrder.id}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Broker Order ID:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.broker_order_id || 'N/A'}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Symbol:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.symbol}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Exchange:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.exchange || 'NSE'}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Transaction Type:</span>
                          <p className={`font-medium ${selectedOrder.transaction_type === 'BUY' ? 'text-green-600' : 'text-red-600'}`}>
                            {selectedOrder.transaction_type}
                          </p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Order Type:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.order_type}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Product:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.product || 'MIS'}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Validity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.validity || 'DAY'}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Quantity & Price Information */}
                  <div className="bg-blue-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">Quantity & Price</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <span className="text-bronze-600 text-sm">Quantity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.quantity}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Filled Quantity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.filled_quantity || selectedOrder.executed_quantity || 0}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Pending Quantity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.pending_quantity || (selectedOrder.quantity - (selectedOrder.executed_quantity || 0))}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Cancelled Quantity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.cancelled_quantity || 0}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Order Price:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.price ? formatCurrency(selectedOrder.price) : 'Market'}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Trigger Price:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.trigger_price ? formatCurrency(selectedOrder.trigger_price) : 'N/A'}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Average Price:</span>
                          <p className="text-bronze-800 font-medium">
                            {selectedOrder.average_price ? formatCurrency(selectedOrder.average_price) : 'N/A'}
                          </p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Disclosed Quantity:</span>
                          <p className="text-bronze-800 font-medium">{selectedOrder.disclosed_quantity || 0}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Status & Timing */}
                <div className="space-y-6">
                  <div className="bg-green-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">Status & Timing</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 gap-4">
                        <div>
                          <span className="text-bronze-600 text-sm">Current Status:</span>
                          <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium border mt-1 ${getStatusColor(selectedOrder.status)}`}>
                            {getStatusIcon(selectedOrder.status)}
                            <span>{selectedOrder.status}</span>
                          </div>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Broker:</span>
                          <p className="text-bronze-800 font-medium capitalize">{selectedOrder.broker_name}</p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Order Time:</span>
                          <p className="text-bronze-800 font-medium">
                            {format(new Date(selectedOrder.created_at), 'MMM dd, yyyy HH:mm:ss')}
                          </p>
                        </div>
                        <div>
                          <span className="text-bronze-600 text-sm">Last Updated:</span>
                          <p className="text-bronze-800 font-medium">
                            {format(new Date(selectedOrder.updated_at), 'MMM dd, yyyy HH:mm:ss')}
                          </p>
                        </div>
                        {selectedOrder.order_timestamp && (
                          <div>
                            <span className="text-bronze-600 text-sm">Exchange Order Time:</span>
                            <p className="text-bronze-800 font-medium">
                              {format(new Date(selectedOrder.order_timestamp), 'MMM dd, yyyy HH:mm:ss')}
                            </p>
                          </div>
                        )}
                        {selectedOrder.exchange_timestamp && (
                          <div>
                            <span className="text-bronze-600 text-sm">Exchange Update Time:</span>
                            <p className="text-bronze-800 font-medium">
                              {format(new Date(selectedOrder.exchange_timestamp), 'MMM dd, yyyy HH:mm:ss')}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* P&L Information */}
                  <div className="bg-purple-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">P&L Information</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 gap-4">
                        <div>
                          <span className="text-bronze-600 text-sm">Realized P&L:</span>
                          <p className={`font-bold text-lg ${getPnLColor(selectedOrder.pnl)}`}>
                            {selectedOrder.pnl > 0 ? '+' : ''}{formatCurrency(selectedOrder.pnl || 0)}
                          </p>
                        </div>
                        {selectedOrder.executed_quantity > 0 && selectedOrder.average_price && (
                          <div>
                            <span className="text-bronze-600 text-sm">Total Value:</span>
                            <p className="text-bronze-800 font-medium">
                              {formatCurrency(selectedOrder.executed_quantity * selectedOrder.average_price)}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Additional Information */}
              <div className="mt-6 space-y-4">
                {/* TradingView Signal */}
                {selectedOrder.webhook_data && (
                  <div className="bg-gray-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">TradingView Signal</h4>
                    <pre className="text-xs text-bronze-700 bg-white p-3 rounded-lg overflow-x-auto border">
                      {JSON.stringify(selectedOrder.webhook_data, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Broker Response */}
                {selectedOrder.status_message && (
                  <div className="bg-gray-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">Broker Response</h4>
                    <pre className="text-xs text-bronze-700 bg-white p-3 rounded-lg overflow-x-auto border">
                      {typeof selectedOrder.status_message === 'string' 
                        ? selectedOrder.status_message 
                        : JSON.stringify(selectedOrder.status_message, null, 2)
                      }
                    </pre>
                  </div>
                )}

                {/* Live Broker Data */}
                {selectedOrder.broker_data && (
                  <div className="bg-gray-50 rounded-xl p-4">
                    <h4 className="font-semibold text-bronze-800 mb-3">Live Broker Data</h4>
                    <pre className="text-xs text-bronze-700 bg-white p-3 rounded-lg overflow-x-auto border">
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