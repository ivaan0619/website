export interface User {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  mobileNumber?: string; // Added mobileNumber as an optional string
}

export interface BrokerConnection {
  id: string;
  brokerId: string;
  brokerName: string;
  isConnected: boolean;
  connectedAt?: string;
}

export interface Order {
  id: string;
  symbol: string;
  quantity: number;
  orderType: 'BUY' | 'SELL';
  price: number;
  status: 'PENDING' | 'EXECUTED' | 'CANCELLED' | 'FAILED';
  timestamp: string;
  pnl?: number;
}

export interface PnLData {
  daily: number;
  weekly: number;
  monthly: number;
  total: number;
  chartData: Array<{
    date: string;
    pnl: number;
  }>;
}

export interface WebhookAlert {
  symbol: string;
  action: 'BUY' | 'SELL';
  quantity: number;
  price?: number;
  orderType: 'MARKET' | 'LIMIT';
}