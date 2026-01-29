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
- Password hashing using SHA-256 for secure passwords
- Rate limiting (100 requests per minute per IP)
- Trade validation to prevent manipulation, server side takes control 
- Suspicious activity logging

## Getting Started

### Prerequisites

- Node.js (v14 or higher)

### Installation

1. Clone the repository
```bash
git clone https://github.com/ronan615/stock-sim-v2.git && cd stock-sim-v2
```
2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start or node server.js
```

4. Open your browser and navigate to:
```
http://localhost:3000
```
5. If you want to deploy on the cloud using port forwarding then forward port 3000

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
- note: this will immediately prompt the user with the multiple choice question
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
- **Styling**: Custom CSS (redone from V1)

## Project Structure

```
stock-sim-v2/
├── server.js           # Main server file which is combined into 1
├── data/              # User and transaction data
│   ├── users.json
│   └── transactions.json
├── package.json
└── README.md
```

## Notes
- No separate HTML files since nodejs server does everything 
- Highly maintainable with minimal components
- Server now handles transactions so no trust is needed on client side to prevent spoofing like the v1