# AutoTraderHub Python API

A FastAPI-based automated trading platform that connects TradingView alerts to broker accounts.

## Features

- **Authentication System**: JWT-based auth with OTP verification
- **Multi-Broker Support**: Connect to Zerodha, Upstox, 5Paisa and more
- **Real-time Order Monitoring**: Live order status updates
- **Webhook Integration**: TradingView alert processing
- **Security**: AES-256 encryption for sensitive data
- **Async Architecture**: High-performance async/await implementation

## Quick Start

### Prerequisites

- Python 3.11+
- pip or poetry

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd autotrader-hub-python
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Environment Setup**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Run the application**
```bash
python run.py
```

The API will be available at `http://localhost:8000`

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f autotrader-api
```

## API Documentation

Once running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **Health Check**: `http://localhost:8000/api/health`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./autotrader.db` |
| `JWT_SECRET_KEY` | JWT signing secret | `your-super-secret-jwt-key` |
| `ENCRYPTION_KEY` | AES encryption key (32 chars) | `autotrader-hub-secret-key-32-chars` |
| `SMTP_HOST` | Email SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | Email SMTP port | `587` |
| `SMTP_USERNAME` | Email username | - |
| `SMTP_PASSWORD` | Email password | - |
| `DEBUG` | Enable debug mode | `True` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `8000` |

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/verify-otp` - OTP verification
- `POST /api/auth/login` - User login
- `POST /api/auth/forgot-password` - Password reset
- `GET /api/auth/me` - Current user info

### Broker Management
- `GET /api/broker/connections` - List broker connections
- `POST /api/broker/connect` - Connect new broker
- `POST /api/broker/reconnect/{id}` - Reconnect broker
- `GET /api/broker/positions/{id}` - Get real-time positions
- `GET /api/broker/holdings/{id}` - Get real-time holdings
- `POST /api/broker/test/{id}` - Test broker connection

### Orders
- `GET /api/orders` - List orders
- `GET /api/orders/{id}` - Get order details
- `POST /api/orders/{id}/start-polling` - Start real-time monitoring
- `POST /api/orders/{id}/stop-polling` - Stop real-time monitoring
- `GET /api/orders/pnl` - P&L analytics

### Webhooks
- `POST /api/webhook/{user_id}/{webhook_id}` - TradingView webhook endpoint

## Architecture

```
app/
├── main.py                 # FastAPI application
├── core/
│   ├── config.py          # Configuration settings
│   ├── database.py        # Database models and setup
│   ├── security.py        # Authentication & encryption
│   ├── logging_config.py  # Logging configuration
│   └── exceptions.py      # Custom exceptions
├── api/
│   └── v1/
│       ├── api.py         # API router
│       └── endpoints/     # API endpoints
├── schemas/               # Pydantic models
├── services/              # Business logic services
└── utils/                 # Utility functions
```

## Security Features

- **JWT Authentication**: Secure token-based authentication
- **AES-256 Encryption**: All sensitive data encrypted at rest
- **Rate Limiting**: API rate limiting to prevent abuse
- **CORS Protection**: Configurable CORS policies
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: SQLAlchemy ORM prevents SQL injection

## Broker Integration

### Zerodha (KiteConnect)
- Real-time order execution
- Position and holdings sync
- OAuth-based authentication
- Live market data

### Adding New Brokers
1. Create broker service in `app/services/`
2. Implement required methods (place_order, get_positions, etc.)
3. Add broker configuration to settings
4. Update API endpoints

## Development

### Running Tests
```bash
pytest
```

### Code Formatting
```bash
black app/
isort app/
```

### Type Checking
```bash
mypy app/
```

## Deployment

### Production Setup
1. Set `DEBUG=False` in environment
2. Use PostgreSQL instead of SQLite
3. Configure proper SMTP settings
4. Set strong JWT secret and encryption key
5. Use reverse proxy (nginx)
6. Enable SSL/TLS

### Environment Variables for Production
```bash
DATABASE_URL=postgresql://user:pass@localhost/autotrader
JWT_SECRET_KEY=your-production-secret-key
ENCRYPTION_KEY=your-production-encryption-key
DEBUG=False
SMTP_HOST=your-smtp-server
SMTP_USERNAME=your-email
SMTP_PASSWORD=your-password
```

## Monitoring

- **Health Check**: `/api/health`
- **Logs**: Structured logging with rotation
- **Metrics**: Order processing metrics
- **Error Tracking**: Comprehensive error logging

## Support

For issues and questions:
1. Check the documentation
2. Review logs in `logs/` directory
3. Check API health endpoint
4. Verify broker connection status

## License

This project is licensed under the MIT License.