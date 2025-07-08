// src/services/api.d.ts

interface AuthAPI {
  register: (formData: any) => Promise<any>;
  login: (formData: any) => Promise<any>;
  getProfile: () => Promise<any>;
  forgotPassword: (data: { identifier: string }) => Promise<any>;
  verifyOtp: (data: { identifier: string; otp: string }) => Promise<any>;
  verifyOtpForReset: (data: { identifier: string; otp: string }) => Promise<any>;
  resetPassword: (data: { resetToken: string; newPassword: string }) => Promise<any>;
  resendOtp: (data: { identifier: string }) => Promise<any>;
}

interface BrokerAPI {
  deleteConnection(connectionId: number): unknown;
  reconnect: any;
  getConnections: () => Promise<any>;
  getConnection: (id: number) => Promise<any>;
  connect: (data: {
    brokerName: string;
    apiKey: string;
    apiSecret: string;
    userId: string;
  }) => Promise<any>;
  disconnect: (connectionId: number) => Promise<any>;
  completeZerodhaAuth: (connectionId: number, requestToken: string) => Promise<any>;
  syncPositions: (connectionId: number) => Promise<any>;
  syncHoldings: (connectionId: number) => Promise<any>;
  getMarketData: (connectionId: number, instruments: string[]) => Promise<any>;
  testConnection: (connectionId: number) => Promise<any>;
}

interface OrdersAPI {
  getOrders: (params?: any) => Promise<any>;
  getOrderDetails: (orderId: string, params?: any) => Promise<any>;
  syncOrders: (brokerConnectionId: number) => Promise<any>;
  updateOrderStatus: (orderId: string, data: any) => Promise<any>;
  getPositions: (params?: any) => Promise<any>;
  getPnL: (params?: any) => Promise<any>;
}

interface WebhookAPI {
  getLogs: (userId: string, params?: any) => Promise<any>;
  testWebhook: (userId: string, webhookId: string) => Promise<any>;
}

export const authAPI: AuthAPI;
export const brokerAPI: BrokerAPI;
export const ordersAPI: OrdersAPI;
export const webhookAPI: WebhookAPI;

export default interface API {
  post: <T = any>(url: string, data?: any) => Promise<T>;
  get: <T = any>(url: string, config?: any) => Promise<T>;
  put: <T = any>(url: string, data?: any) => Promise<T>;
  delete: <T = any>(url: string) => Promise<T>;
  patch: <T = any>(url: string, data?: any) => Promise<T>;
}
