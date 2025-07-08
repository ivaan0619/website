import React from 'react';
import { motion } from 'framer-motion';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { TrendingUp, TrendingDown, DollarSign, Calendar } from 'lucide-react';

const PnL: React.FC = () => {
  const [selectedPeriod, setSelectedPeriod] = React.useState('1M');

  const dailyPnL = [
    { date: '2024-01-08', pnl: 1200, trades: 5 },
    { date: '2024-01-09', pnl: -800, trades: 3 },
    { date: '2024-01-10', pnl: 2100, trades: 7 },
    { date: '2024-01-11', pnl: 500, trades: 4 },
    { date: '2024-01-12', pnl: -300, trades: 2 },
    { date: '2024-01-13', pnl: 1800, trades: 6 },
    { date: '2024-01-14', pnl: 700, trades: 8 },
    { date: '2024-01-15', pnl: 2300, trades: 9 }
  ];

  const monthlyStats = [
    { month: 'Oct', pnl: 12500, winRate: 75 },
    { month: 'Nov', pnl: 8900, winRate: 68 },
    { month: 'Dec', pnl: 15600, winRate: 82 },
    { month: 'Jan', pnl: 18200, winRate: 78 }
  ];

  const totalPnL = dailyPnL.reduce((sum, day) => sum + day.pnl, 0);
  const totalTrades = dailyPnL.reduce((sum, day) => sum + day.trades, 0);
  const winningDays = dailyPnL.filter(day => day.pnl > 0).length;
  const winRate = (winningDays / dailyPnL.length) * 100;

  const periods = ['1W', '1M', '3M', '6M', '1Y'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white">P&L Analytics</h1>
          <p className="text-olive-200/70 mt-1">Track your trading performance and profitability</p>
        </div>
        <div className="flex items-center space-x-2 mt-4 sm:mt-0">
          {periods.map((period) => (
            <button
              key={period}
              onClick={() => setSelectedPeriod(period)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedPeriod === period
                  ? 'bg-olive-600 text-white'
                  : 'bg-dark-800/50 text-olive-200 hover:bg-olive-800/20'
              }`}
            >
              {period}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-gradient-to-r from-olive-500 to-olive-600 rounded-lg flex items-center justify-center">
              <DollarSign className="w-6 h-6 text-white" />
            </div>
            <TrendingUp className="w-5 h-5 text-olive-400" />
          </div>
          <h3 className="text-2xl font-bold text-white mb-1">₹{totalPnL.toLocaleString()}</h3>
          <p className="text-olive-200/70">Total P&L</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-gradient-to-r from-olive-600 to-olive-700 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-white" />
            </div>
            <div className="text-olive-400 text-sm font-medium">+12.3%</div>
          </div>
          <h3 className="text-2xl font-bold text-white mb-1">{winRate.toFixed(1)}%</h3>
          <p className="text-olive-200/70">Win Rate</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-gradient-to-r from-dark-600 to-olive-600 rounded-lg flex items-center justify-center">
              <Calendar className="w-6 h-6 text-olive-300" />
            </div>
            <div className="text-olive-400 text-sm font-medium">Active</div>
          </div>
          <h3 className="text-2xl font-bold text-white mb-1">{totalTrades}</h3>
          <p className="text-olive-200/70">Total Trades</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-gradient-to-r from-red-600 to-red-700 rounded-lg flex items-center justify-center">
              <TrendingDown className="w-6 h-6 text-white" />
            </div>
            <div className="text-red-400 text-sm font-medium">-5.2%</div>
          </div>
          <h3 className="text-2xl font-bold text-white mb-1">₹2,100</h3>
          <p className="text-olive-200/70">Max Drawdown</p>
        </motion.div>
      </div>

      {/* Daily P&L Chart */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">Daily P&L Trend</h2>
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-olive-500 rounded-full"></div>
              <span className="text-olive-200">P&L</span>
            </div>
          </div>
        </div>
        
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={dailyPnL}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(138, 156, 112, 0.1)" />
              <XAxis 
                dataKey="date" 
                stroke="#8a9c70"
                fontSize={12}
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              />
              <YAxis stroke="#8a9c70" fontSize={12} />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'rgba(26, 26, 26, 0.95)',
                  border: '1px solid rgba(138, 156, 112, 0.2)',
                  borderRadius: '8px',
                  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                  color: '#8a9c70'
                }}
                formatter={(value: number) => [`₹${value}`, 'P&L']}
                labelFormatter={(label) => `Date: ${new Date(label).toLocaleDateString()}`}
              />
              <Line 
                type="monotone" 
                dataKey="pnl" 
                stroke="#8a9c70" 
                strokeWidth={3}
                dot={{ fill: '#8a9c70', strokeWidth: 2, r: 4 }}
                activeDot={{ r: 6, stroke: '#8a9c70', strokeWidth: 2, fill: 'white' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      {/* Monthly Performance */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="bg-dark-800/50 backdrop-blur-xl rounded-2xl p-6 shadow-xl border border-olive-500/20"
      >
        <h2 className="text-xl font-bold text-white mb-6">Monthly Performance</h2>
        
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={monthlyStats}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(138, 156, 112, 0.1)" />
              <XAxis dataKey="month" stroke="#8a9c70" fontSize={12} />
              <YAxis stroke="#8a9c70" fontSize={12} />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'rgba(26, 26, 26, 0.95)',
                  border: '1px solid rgba(138, 156, 112, 0.2)',
                  borderRadius: '8px',
                  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                  color: '#8a9c70'
                }}
                formatter={(value: number, name: string) => [
                  name === 'pnl' ? `₹${value}` : `${value}%`,
                  name === 'pnl' ? 'P&L' : 'Win Rate'
                ]}
              />
              <Bar 
                dataKey="pnl" 
                fill="#8a9c70" 
                radius={[4, 4, 0, 0]}
                name="pnl"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </motion.div>
    </div>
  );
};

export default PnL;