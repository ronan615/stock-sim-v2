# Stock Trading Simulator v2

A modern stock trading simulator with real-time market data and a Robinhood-inspired interface.

## Features

- **Real-time Stock Data**: Live prices from Yahoo Finance API
- **User Authentication**: Secure login and registration system
- **Portfolio Management**: Track your investments and performance
- **Interactive Charts**: Visualize stock performance across multiple timeframes
- **Leaderboard**: Compete with other traders
- **Transaction History**: View all your past trades
- **Anti-Cheat System**: Rate limiting, suspicious activity detection, and trade validation
- **Modern UI**: Robinhood-inspired dark theme interface

## Security Features

- Session-based authentication with token expiration
- Password hashing using SHA-256
- Rate limiting (100 requests per minute per IP)
- Trade validation to prevent manipulation
- Suspicious activity logging
- Request integrity checks

## Getting Started

### Prerequisites

- Node.js (v14 or higher)

### Installation

1. Clone the repository
2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

4. Open your browser and navigate to:
```
http://localhost:3000
```

### Development Mode

For auto-restart on file changes:
```bash
npm run dev
```

## Usage

1. **Create an Account**: Register with a username and password
2. **Search Stocks**: Use the search bar to find stocks (e.g., AAPL, TSLA, GOOGL)
3. **Trade**: Buy and sell stocks with your virtual $100,000 starting balance
4. **Track Performance**: Monitor your portfolio value and compare with others on the leaderboard

## API Endpoints

### Authentication
- `POST /api/register` - Create new account
- `POST /api/login` - Login to existing account

### Trading
- `GET /api/portfolio` - Get user portfolio
- `POST /api/buy` - Buy stocks
- `POST /api/sell` - Sell stocks
- `GET /api/stock/:symbol` - Get stock data and chart

### Data
- `GET /api/leaderboard` - Get top traders
- `GET /api/transactions` - Get user transaction history

## Tech Stack

- **Backend**: Node.js, Express
- **Frontend**: Vanilla JavaScript, Chart.js
- **Data Source**: Yahoo Finance API
- **Styling**: Custom CSS (Robinhood-inspired)

## Project Structure

```
stock-sim-v2/
├── server.js           # Main server file (backend + frontend)
├── data/              # User and transaction data
│   ├── users.json
│   └── transactions.json
├── package.json
└── README.md
```

## Notes

- All communication is over HTTPS when deployed
- No separate HTML files - server serves everything
- Highly maintainable with minimal comments
- Strong emphasis on security and fair play
- Compatible with Cloudflare Tunnel (no TCP requests)

## License

MIT
