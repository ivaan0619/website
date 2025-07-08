import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  TrendingUp, TrendingDown, RefreshCw, Activity, DollarSign, 
  Target, BarChart3, AlertTriangle, Wifi, WifiOff, Eye, EyeOff,
  Zap, Clock, ArrowUpRight, ArrowDownRight, Briefcase, PieChart
} from 'lucide-react';
import { brokerAPI } from '../../services/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';

interface Position {
  tradingsymbol: string;
  exchange: string;
  instrument_token: number;
  product: string;
  quantity: number;
  overnight_quantity: number;
  multiplier: number;
  average_price: number;
  close_price: number;
  last_price: number;
  value: number;
  pnl: number;
  m2m: number;
  unrealised: number;
  realised: number;
  buy_quantity: number;
  buy_price: number;
  buy_value: number;
  sell_quantity: number;
  sell_price: number;
  sell_value: number;
  day_buy_quantity: number;
  day_buy_price: number;
  day_buy_value: number;
  day_sell_quantity: number;
  day_sell_price: number;
  day_sell_value: number;
  broker_name?: string;
  connection_id?: number;
  last_updated?: string;
}

interface Holding {
  tradingsymbol: string;
  exchange: string;
  instrument_token: number;
  isin: string;
  product: string;
  price: number;
  quantity: number;
  used_quantity: number;
  t1_quantity: number;
  realised_quantity: number;
  authorised_quantity: number;
  authorised_date: string;
  opening_quantity: number;
  collateral_quantity: number;
  collateral_type: string;
  discrepancy: boolean;
  average_price: number;
  last_price: number;
  close_price: number;
  pnl: number;
  day_change: number;
  day_change_percentage: number;
  broker_name?: string;
  connection_id?: number;
  last_updated?: string;
}

interface PnLSummary {
  total_pnl: number;
  total_investment: number;
  total_current_value: number;
  total_positions: number;
  profitable_positions: number;
  loss_positions: number;
  largest_gain: number;
  largest_loss: number;
}

const Positions: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'positions' | 'holdings'>('positions');
  const [positions, setPositions] = useState<Position[]>([]);
  const [holdings, setHoldings] = useState<Holding[]>([]);
  const [pnlSummary, setPnlSummary] = useState<PnLSummary | null>(null);
  const [brokerConnections, setBrokerConnections] = useState<any[]>([]);
  const [selectedBroker, setSelectedBroker] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [isLiveUpdating, setIsLiveUpdating] = useState(false);
  const [lastUpdateTime, setLastUpdateTime] = useState<Date | null>(null);
  const [positionUpdateInterval, setPositionUpdateInterval] = useState(5000); // 5 seconds
  const [holdingUpdateInterval, setHoldingUpdateInterval] = useState(3600000); // 1 hour
  const [showDetails, setShowDetails] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<{[key: number]: boolean}>({});
  const positionIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const holdingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isComponentMounted = useRef(true);

  useEffect(() => {
    fetchInitialData();
    
    return () => {
      isComponentMounted.current = false;
      stopLiveUpdates();
    };
  }, []);

  useEffect(() => {
    if (isLiveUpdating) {
      startLiveUpdates();
    } else {
      stopLiveUpdates();
    }
    
    return () => stopLiveUpdates();
  }, [isLiveUpdating, positionUpdateInterval, holdingUpdateInterval, selectedBroker, activeTab]);

  const fetchInitialData = async () => {
    try {
      setLoading(true);
      const connectionsResponse = await brokerAPI.getConnections();
      const activeConnections = connectionsResponse.data.connections.filter(
        (conn: any) => conn.is_active && conn.is_authenticated
      );
      setBrokerConnections(activeConnections);
      
      if (activeConnections.length > 0) {
        await Promise.all([
          fetchPositionsData(),
          fetchHoldingsData()
        ]);
      }
    } catch (error) {
      console.error('Failed to fetch initial data:', error);
      toast.error('Failed to load broker connections');
    } finally {
      setLoading(false);
    }
  };

  const fetchPositionsData = React.useCallback(async () => {
    try {
      const activeConnections = brokerConnections.filter(
        conn => selectedBroker === 'all' || conn.id.toString() === selectedBroker
      );

      if (activeConnections.length === 0) {
        setPositions([]);
        return;
      }

      const allPositions: Position[] = [];
      const connectionStatuses: {[key: number]: boolean} = {};

      for (const connection of activeConnections) {
        try {
          const response = await brokerAPI.getPositions(connection.id);
          connectionStatuses[connection.id] = true;
          
          if (response.data.positions && response.data.positions.length > 0) {
            const formattedPositions = response.data.positions.map((pos: any) => ({
              ...pos,
              broker_name: connection.broker_name,
              connection_id: connection.id,
              last_updated: new Date().toISOString()
            }));
            
            allPositions.push(...formattedPositions);
          }
        } catch (error) {
          console.error(`Failed to fetch positions from ${connection.broker_name}:`, error);
          connectionStatuses[connection.id] = false;
        }
      }

      // Filter out zero quantity positions
      const activePositions = allPositions.filter(pos => Math.abs(pos.quantity) > 0);
      
      setPositions(activePositions);
      setConnectionStatus(connectionStatuses);
      calculatePnLSummary(activePositions, holdings);
      setLastUpdateTime(new Date());
      
    } catch (error) {
      console.error('Failed to fetch positions:', error);
      if (isComponentMounted.current) {
        toast.error('Failed to fetch positions');
      }
    }
  }, [brokerConnections, selectedBroker, holdings]);

  const fetchHoldingsData = React.useCallback(async () => {
    try {
      const activeConnections = brokerConnections.filter(
        conn => selectedBroker === 'all' || conn.id.toString() === selectedBroker
      );

      if (activeConnections.length === 0) {
        setHoldings([]);
        return;
      }

      const allHoldings: Holding[] = [];
      const connectionStatuses: {[key: number]: boolean} = {};

      for (const connection of activeConnections) {
        try {
          const response = await brokerAPI.getHoldings(connection.id);
          connectionStatuses[connection.id] = true;
          
          if (response.data.holdings && response.data.holdings.length > 0) {
            const formattedHoldings = response.data.holdings.map((holding: any) => ({
              ...holding,
              broker_name: connection.broker_name,
              connection_id: connection.id,
              last_updated: new Date().toISOString()
            }));
            
            allHoldings.push(...formattedHoldings);
          }
        } catch (error) {
          console.error(`Failed to fetch holdings from ${connection.broker_name}:`, error);
          connectionStatuses[connection.id] = false;
        }
      }

      // Filter out zero quantity holdings
      const activeHoldings = allHoldings.filter(holding => Math.abs(holding.quantity) > 0);
      
      setHoldings(activeHoldings);
      setConnectionStatus(prev => ({ ...prev, ...connectionStatuses }));
      calculatePnLSummary(positions, activeHoldings);
      setLastUpdateTime(new Date());
      
    } catch (error) {
      console.error('Failed to fetch holdings:', error);
      if (isComponentMounted.current) {
        toast.error('Failed to fetch holdings');
      }
    }
  }, [brokerConnections, selectedBroker, positions]);

  const calculatePnLSummary = React.useCallback((positions: Position[], holdings: Holding[]) => {
    const summary: PnLSummary = {
      total_pnl: 0,
      total_investment: 0,
      total_current_value: 0,
      total_positions: positions.length + holdings.length,
      profitable_positions: 0,
      loss_positions: 0,
      largest_gain: 0,
      largest_loss: 0
    };

    // Calculate for positions
    positions.forEach(pos => {
      const pnl = pos.pnl || pos.unrealised || 0;
      const investment = Math.abs(pos.quantity) * pos.average_price;
      const currentValue = Math.abs(pos.quantity) * pos.last_price;

      summary.total_pnl += pnl;
      summary.total_investment += investment;
      summary.total_current_value += currentValue;

      if (pnl > 0) {
        summary.profitable_positions++;
        summary.largest_gain = Math.max(summary.largest_gain, pnl);
      } else if (pnl < 0) {
        summary.loss_positions++;
        summary.largest_loss = Math.min(summary.largest_loss, pnl);
      }
    });

    // Calculate for holdings
    holdings.forEach(holding => {
      const pnl = holding.pnl || 0;
      const investment = holding.quantity * holding.average_price;
      const currentValue = holding.quantity * holding.last_price;

      summary.total_pnl += pnl;
      summary.total_investment += investment;
      summary.total_current_value += currentValue;

      if (pnl > 0) {
        summary.profitable_positions++;
        summary.largest_gain = Math.max(summary.largest_gain, pnl);
      } else if (pnl < 0) {
        summary.loss_positions++;
        summary.largest_loss = Math.min(summary.largest_loss, pnl);
      }
    });

    setPnlSummary(summary);
  }, []);

  const startLiveUpdates = React.useCallback(() => {
    stopLiveUpdates();
    
    if (brokerConnections.length === 0) {
      toast.error('No active broker connections to start live updates.');
      return;
    }
    
    // Start position updates (every 5 seconds by default)
    positionIntervalRef.current = setInterval(() => {
      if (isComponentMounted.current && (activeTab === 'positions' || activeTab === 'positions')) {
        fetchPositionsData();
      }
    }, positionUpdateInterval);

    // Start holding updates (every 1 hour by default)
    holdingIntervalRef.current = setInterval(() => {
      if (isComponentMounted.current && (activeTab === 'holdings' || activeTab === 'positions')) {
        fetchHoldingsData();
      }
    }, holdingUpdateInterval);
  }, [brokerConnections, positionUpdateInterval, holdingUpdateInterval, fetchPositionsData, fetchHoldingsData, activeTab]);

  const stopLiveUpdates = () => {
    if (positionIntervalRef.current) {
      clearInterval(positionIntervalRef.current);
      positionIntervalRef.current = null;
    }
    if (holdingIntervalRef.current) {
      clearInterval(holdingIntervalRef.current);
      holdingIntervalRef.current = null;
    }
  };

  const toggleLiveUpdates = () => {
    setIsLiveUpdating(!isLiveUpdating);
    if (!isLiveUpdating) {
      toast.success(`Live updates started`);
    } else {
      toast.success('Live updates stopped');
    }
  };

  const handleManualRefresh = async () => {
    if (activeTab === 'positions') {
      await fetchPositionsData();
    } else {
      await fetchHoldingsData();
    }
    toast.success(`${activeTab} refreshed`);
  };

  const getPnLColor = (pnl: number) => {
    if (pnl > 0) return 'text-green-600';
    if (pnl < 0) return 'text-red-600';
    return 'text-bronze-600';
  };

  const getPnLBgColor = (pnl: number) => {
    if (pnl > 0) return 'bg-green-50 border-green-200';
    if (pnl < 0) return 'bg-red-50 border-red-200';
    return 'bg-gray-50 border-gray-200';
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  };

  const formatPercentage = (percentage: number) => {
    return `${percentage > 0 ? '+' : ''}${percentage.toFixed(2)}%`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Controls */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-bronze-800 flex items-center">
            <Activity className="w-8 h-8 mr-3 text-amber-600" />
            Portfolio Overview
          </h1>
          <p className="text-bronze-600 mt-1">
            Real-time positions and holdings directly from your broker accounts
          </p>
          {lastUpdateTime && (
            <p className="text-bronze-500 text-sm mt-1">
              Last updated: {format(lastUpdateTime, 'HH:mm:ss')}
            </p>
          )}
        </div>
        
        <div className="flex items-center space-x-3 mt-4 sm:mt-0">
          {/* Broker Filter */}
          <select
            value={selectedBroker}
            onChange={(e) => setSelectedBroker(e.target.value)}
            className="px-4 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
          >
            <option value="all">All Brokers</option>
            {brokerConnections.map(broker => (
              <option key={broker.id} value={broker.id.toString()}>
                {broker.broker_name.charAt(0).toUpperCase() + broker.broker_name.slice(1)}
                {connectionStatus[broker.id] === false && ' (Error)'}
              </option>
            ))}
          </select>

          {/* Update Intervals */}
          {activeTab === 'positions' && (
            <select
              value={positionUpdateInterval}
              onChange={(e) => setPositionUpdateInterval(Number(e.target.value))}
              className="px-3 py-2 bg-cream-50 border border-beige-200 rounded-lg text-bronze-800 text-sm focus:ring-2 focus:ring-amber-500 focus:border-transparent"
            >
              <option value={1000}>1s</option>
              <option value={3000}>3s</option>
              <option value={5000}>5s</option>
              <option value={10000}>10s</option>
              <option value={30000}>30s</option>
            </select>
          )}

          {/* Manual Refresh */}
          <motion.button
            onClick={handleManualRefresh}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 bg-amber-600 text-white px-4 py-2 rounded-lg hover:bg-amber-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </motion.button>

          {/* Live Updates Toggle */}
          <motion.button
            onClick={toggleLiveUpdates}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              isLiveUpdating
                ? 'bg-green-600 text-white hover:bg-green-700'
                : 'bg-bronze-200 text-bronze-800 hover:bg-bronze-300'
            }`}
          >
            {isLiveUpdating ? (
              <>
                <Wifi className="w-4 h-4 animate-pulse" />
                <span>Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4" />
                <span>Start Live</span>
              </>
            )}
          </motion.button>

          {/* Details Toggle */}
          <motion.button
            onClick={() => setShowDetails(!showDetails)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 bg-bronze-600 text-white px-4 py-2 rounded-lg hover:bg-bronze-700 transition-colors"
          >
            {showDetails ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            <span>{showDetails ? 'Hide' : 'Show'} Details</span>
          </motion.button>
        </div>
      </motion.div>

      {/* P&L Summary Cards */}
      {pnlSummary && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          <motion.div
            whileHover={{ scale: 1.02, rotateY: 2 }}
            className={`bg-white/80 backdrop-blur-xl rounded-2xl p-6 shadow-3d border ${getPnLBgColor(pnlSummary.total_pnl)}`}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-gradient-to-r from-amber-500 to-bronze-600 rounded-lg flex items-center justify-center">
                <DollarSign className="w-6 h-6 text-white" />
              </div>
              {pnlSummary.total_pnl > 0 ? (
                <ArrowUpRight className="w-5 h-5 text-green-600" />
              ) : (
                <ArrowDownRight className="w-5 h-5 text-red-600" />
              )}
            </div>
            <h3 className={`text-2xl font-bold mb-1 ${getPnLColor(pnlSummary.total_pnl)}`}>
              {formatCurrency(pnlSummary.total_pnl)}
            </h3>
            <p className="text-bronze-600">Total P&L</p>
            {isLiveUpdating && (
              <div className="mt-2 flex items-center space-x-1">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-600">Live</span>
              </div>
            )}
          </motion.div>

          <motion.div
            whileHover={{ scale: 1.02, rotateY: 2 }}
            className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 shadow-3d border border-beige-200"
          >
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
                <Target className="w-6 h-6 text-white" />
              </div>
              <div className="text-bronze-600 text-sm font-medium">
                {pnlSummary.total_positions} items
              </div>
            </div>
            <h3 className="text-2xl font-bold text-bronze-800 mb-1">
              {formatCurrency(pnlSummary.total_current_value)}
            </h3>
            <p className="text-bronze-600">Current Value</p>
          </motion.div>

          <motion.div
            whileHover={{ scale: 1.02, rotateY: 2 }}
            className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 shadow-3d border border-beige-200"
          >
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-lg flex items-center justify-center">
                <TrendingUp className="w-6 h-6 text-white" />
              </div>
              <div className="text-green-600 text-sm font-medium">
                {pnlSummary.profitable_positions} profitable
              </div>
            </div>
            <h3 className="text-2xl font-bold text-green-600 mb-1">
              {formatCurrency(pnlSummary.largest_gain)}
            </h3>
            <p className="text-bronze-600">Largest Gain</p>
          </motion.div>

          <motion.div
            whileHover={{ scale: 1.02, rotateY: 2 }}
            className="bg-white/80 backdrop-blur-xl rounded-2xl p-6 shadow-3d border border-beige-200"
          >
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-gradient-to-r from-red-500 to-red-600 rounded-lg flex items-center justify-center">
                <TrendingDown className="w-6 h-6 text-white" />
              </div>
              <div className="text-red-600 text-sm font-medium">
                {pnlSummary.loss_positions} in loss
              </div>
            </div>
            <h3 className="text-2xl font-bold text-red-600 mb-1">
              {formatCurrency(pnlSummary.largest_loss)}
            </h3>
            <p className="text-bronze-600">Largest Loss</p>
          </motion.div>
        </motion.div>
      )}

      {/* Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-3d border border-beige-200"
      >
        <div className="flex border-b border-beige-200">
          <motion.button
            onClick={() => setActiveTab('positions')}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className={`flex-1 px-6 py-4 font-medium transition-colors flex items-center justify-center space-x-2 ${
              activeTab === 'positions'
                ? 'text-amber-600 border-b-2 border-amber-600 bg-amber-50'
                : 'text-bronze-600 hover:text-amber-600'
            }`}
          >
            <Activity className="w-5 h-5" />
            <span>Positions ({positions.length})</span>
            {isLiveUpdating && activeTab === 'positions' && (
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            )}
          </motion.button>
          
          <motion.button
            onClick={() => setActiveTab('holdings')}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className={`flex-1 px-6 py-4 font-medium transition-colors flex items-center justify-center space-x-2 ${
              activeTab === 'holdings'
                ? 'text-amber-600 border-b-2 border-amber-600 bg-amber-50'
                : 'text-bronze-600 hover:text-amber-600'
            }`}
          >
            <Briefcase className="w-5 h-5" />
            <span>Holdings ({holdings.length})</span>
            {isLiveUpdating && activeTab === 'holdings' && (
              <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
            )}
          </motion.button>
        </div>

        {/* Positions Tab Content */}
        <AnimatePresence mode="wait">
          {activeTab === 'positions' && (
            <motion.div
              key="positions"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              {positions.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-amber-50">
                      <tr>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Symbol</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Qty</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Avg Price</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">LTP</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">P&L</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">P&L %</th>
                        {showDetails && (
                          <>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">Value</th>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">Product</th>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">Broker</th>
                          </>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      <AnimatePresence>
                        {positions.map((position, index) => {
                          const pnl = position.pnl || position.unrealised || 0;
                          const pnlPercentage = position.average_price > 0 ? (pnl / (Math.abs(position.quantity) * position.average_price)) * 100 : 0;

                          return (
                            <motion.tr
                              key={`${position.tradingsymbol}-${position.connection_id}`}
                              initial={{ opacity: 0, y: 20 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -20 }}
                              transition={{ delay: index * 0.05 }}
                              className="border-b border-beige-100 hover:bg-amber-50/50 transition-colors"
                            >
                              <td className="py-4 px-6">
                                <div className="flex flex-col">
                                  <span className="font-medium text-bronze-800">{position.tradingsymbol}</span>
                                  <span className="text-xs text-bronze-600">{position.exchange}</span>
                                </div>
                              </td>
                              <td className="py-4 px-6">
                                <div className="flex items-center space-x-2">
                                  {position.quantity > 0 ? (
                                    <TrendingUp className="w-4 h-4 text-green-600" />
                                  ) : (
                                    <TrendingDown className="w-4 h-4 text-red-600" />
                                  )}
                                  <span className={`font-medium ${
                                    position.quantity > 0 ? 'text-green-600' : 'text-red-600'
                                  }`}>
                                    {Math.abs(position.quantity)}
                                  </span>
                                </div>
                              </td>
                              <td className="py-4 px-6 text-bronze-800">
                                {formatCurrency(position.average_price)}
                              </td>
                              <td className="py-4 px-6">
                                <div className="flex items-center space-x-2">
                                  <span className="text-bronze-800 font-medium">
                                    {formatCurrency(position.last_price)}
                                  </span>
                                  {isLiveUpdating && (
                                    <Zap className="w-3 h-3 text-yellow-500 animate-pulse" />
                                  )}
                                </div>
                              </td>
                              <td className="py-4 px-6">
                                <span className={`font-bold ${getPnLColor(pnl)}`}>
                                  {pnl > 0 ? '+' : ''}{formatCurrency(pnl)}
                                </span>
                              </td>
                              <td className="py-4 px-6">
                                <span className={`font-medium ${getPnLColor(pnl)}`}>
                                  {formatPercentage(pnlPercentage)}
                                </span>
                              </td>
                              {showDetails && (
                                <>
                                  <td className="py-4 px-6 text-bronze-800">
                                    {formatCurrency(position.value || (Math.abs(position.quantity) * position.last_price))}
                                  </td>
                                  <td className="py-4 px-6 text-bronze-800">
                                    {position.product}
                                  </td>
                                  <td className="py-4 px-6">
                                    <div className="flex items-center space-x-2">
                                      <span className="text-bronze-800 capitalize">
                                        {position.broker_name}
                                      </span>
                                      {connectionStatus[position.connection_id!] === false && (
                                        <AlertTriangle className="w-4 h-4 text-red-600" />
                                      )}
                                    </div>
                                  </td>
                                </>
                              )}
                            </motion.tr>
                          );
                        })}
                      </AnimatePresence>
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-12">
                  <Activity className="w-16 h-16 text-amber-400/50 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-bronze-800 mb-2">No Active Positions</h3>
                  <p className="text-bronze-600">
                    {brokerConnections.length === 0 
                      ? 'Connect a broker account to see your positions'
                      : 'You currently have no open positions'
                    }
                  </p>
                </div>
              )}
            </motion.div>
          )}

          {/* Holdings Tab Content */}
          {activeTab === 'holdings' && (
            <motion.div
              key="holdings"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              {holdings.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-blue-50">
                      <tr>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Symbol</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Qty</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Avg Price</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">LTP</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">P&L</th>
                        <th className="text-left py-4 px-6 font-semibold text-bronze-800">Day Change</th>
                        {showDetails && (
                          <>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">Value</th>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">T1 Qty</th>
                            <th className="text-left py-4 px-6 font-semibold text-bronze-800">Broker</th>
                          </>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      <AnimatePresence>
                        {holdings.map((holding, index) => {
                          const pnl = holding.pnl || 0;
                          const dayChange = holding.day_change || 0;
                          const dayChangePercentage = holding.day_change_percentage || 0;

                          return (
                            <motion.tr
                              key={`${holding.tradingsymbol}-${holding.connection_id}`}
                              initial={{ opacity: 0, y: 20 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -20 }}
                              transition={{ delay: index * 0.05 }}
                              className="border-b border-beige-100 hover:bg-blue-50/50 transition-colors"
                            >
                              <td className="py-4 px-6">
                                <div className="flex flex-col">
                                  <span className="font-medium text-bronze-800">{holding.tradingsymbol}</span>
                                  <span className="text-xs text-bronze-600">{holding.exchange}</span>
                                </div>
                              </td>
                              <td className="py-4 px-6">
                                <div className="flex flex-col">
                                  <span className="font-medium text-bronze-800">{holding.quantity}</span>
                                  {holding.used_quantity > 0 && (
                                    <span className="text-xs text-amber-600">Used: {holding.used_quantity}</span>
                                  )}
                                </div>
                              </td>
                              <td className="py-4 px-6 text-bronze-800">
                                {formatCurrency(holding.average_price)}
                              </td>
                              <td className="py-4 px-6">
                                <div className="flex items-center space-x-2">
                                  <span className="text-bronze-800 font-medium">
                                    {formatCurrency(holding.last_price)}
                                  </span>
                                  {isLiveUpdating && (
                                    <Clock className="w-3 h-3 text-blue-500 animate-pulse" />
                                  )}
                                </div>
                              </td>
                              <td className="py-4 px-6">
                                <span className={`font-bold ${getPnLColor(pnl)}`}>
                                  {pnl > 0 ? '+' : ''}{formatCurrency(pnl)}
                                </span>
                              </td>
                              <td className="py-4 px-6">
                                <div className="flex flex-col">
                                  <span className={`font-medium ${getPnLColor(dayChange)}`}>
                                    {dayChange > 0 ? '+' : ''}{formatCurrency(dayChange)}
                                  </span>
                                  <span className={`text-xs ${getPnLColor(dayChange)}`}>
                                    {formatPercentage(dayChangePercentage)}
                                  </span>
                                </div>
                              </td>
                              {showDetails && (
                                <>
                                  <td className="py-4 px-6 text-bronze-800">
                                    {formatCurrency(holding.quantity * holding.last_price)}
                                  </td>
                                  <td className="py-4 px-6 text-bronze-800">
                                    {holding.t1_quantity}
                                  </td>
                                  <td className="py-4 px-6">
                                    <div className="flex items-center space-x-2">
                                      <span className="text-bronze-800 capitalize">
                                        {holding.broker_name}
                                      </span>
                                      {connectionStatus[holding.connection_id!] === false && (
                                        <AlertTriangle className="w-4 h-4 text-red-600" />
                                      )}
                                    </div>
                                  </td>
                                </>
                              )}
                            </motion.tr>
                          );
                        })}
                      </AnimatePresence>
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-12">
                  <Briefcase className="w-16 h-16 text-blue-400/50 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-bronze-800 mb-2">No Holdings</h3>
                  <p className="text-bronze-600">
                    {brokerConnections.length === 0 
                      ? 'Connect a broker account to see your holdings'
                      : 'You currently have no holdings'
                    }
                  </p>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Connection Status */}
      {brokerConnections.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white/60 backdrop-blur-xl rounded-xl p-4 border border-beige-200"
        >
          <h3 className="text-sm font-medium text-bronze-800 mb-3">Broker Connection Status</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {brokerConnections.map(broker => (
              <div key={broker.id} className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  connectionStatus[broker.id] === false 
                    ? 'bg-red-400' 
                    : 'bg-green-400 animate-pulse'
                }`}></div>
                <span className="text-bronze-800 capitalize">{broker.broker_name}</span>
                {connectionStatus[broker.id] === false && (
                  <span className="text-xs text-red-600">Connection Error</span>
                )}
                {isLiveUpdating && connectionStatus[broker.id] !== false && (
                  <span className="text-xs text-green-600">
                    {activeTab === 'positions' ? `${positionUpdateInterval/1000}s` : '1h'} updates
                  </span>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default Positions;