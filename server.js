const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TRANSACTIONS_FILE = path.join(DATA_DIR, 'transactions.json');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

let users = {};
let transactions = [];
const activeSessions = new Map();
const requestCounts = new Map();
const suspiciousActivity = new Map();
//non hard coded tutorial lessons so you can add more later here if you fork the repository just make sure it follows the same format
const TUTORIAL_LESSONS = [ 
    {
        id: 'stocks-basics',
        title: 'Understanding Stocks',
        content: 'A stock represents partial ownership in a company. When you buy a share of stock, you become a shareholder and own a piece of that business. Stock prices fluctuate based on company performance, market conditions, and investor sentiment.',
        question: 'What does owning a stock represent?',
        options: [
            'Lending money to a company',
            'Partial ownership in a company',
            'A guaranteed monthly payment',
            'Debt from the company'
        ],
        correctAnswer: 1
    },
    {
        id: 'supply-demand',
        title: 'Supply and Demand',
        content: 'Stock prices are determined by supply and demand. When more people want to buy a stock (high demand) than sell it (low supply), the price goes up. When more people want to sell than buy, the price falls. This is the fundamental principle of market pricing.',
        question: 'What happens to a stock price when demand significantly exceeds supply?',
        options: [
            'The price decreases',
            'The price stays the same',
            'The price increases',
            'Trading is halted'
        ],
        correctAnswer: 2
    },
    {
        id: 'risk-reward',
        title: 'Risk and Reward',
        content: 'All investments carry risk. Generally, higher potential returns come with higher risk. Understanding your risk tolerance is crucial before investing. Diversification—spreading investments across different assets—can help manage risk.',
        question: 'What is the relationship between risk and potential reward in investing?',
        options: [
            'Lower risk usually means higher reward',
            'Higher risk usually means higher potential reward',
            'Risk and reward are unrelated',
            'Higher risk guarantees higher reward'
        ],
        correctAnswer: 1
    },
    {
        id: 'market-orders',
        title: 'Market Orders',
        content: 'A market order is an instruction to buy or sell a stock immediately at the current market price. It prioritizes speed over price. Market orders are executed quickly but the final price may differ slightly from what you saw when placing the order.',
        question: 'What is the main advantage of a market order?',
        options: [
            'You get the best possible price',
            'It executes immediately at current market price',
            'You can set a specific price',
            'It never loses money'
        ],
        correctAnswer: 1
    },
    {
        id: 'portfolio-diversification',
        title: 'Building a Portfolio',
        content: 'A portfolio is your collection of investments. Diversification means not putting all your eggs in one basket—spreading investments across different companies, sectors, and asset types reduces risk. If one investment performs poorly, others may balance it out.',
        question: 'Why is portfolio diversification important?',
        options: [
            'To maximize risk exposure',
            'To reduce the impact of any single investment failing',
            'To avoid paying taxes',
            'To guarantee profits'
        ],
        correctAnswer: 1
    }
];

const loadData = () => {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            users = JSON.parse(data);
        }
        if (fs.existsSync(TRANSACTIONS_FILE)) {
            const data = fs.readFileSync(TRANSACTIONS_FILE, 'utf8');
            transactions = JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading data:', error);
    }
};

const saveUsers = () => {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('Error saving users:', error);
    }
};

const saveTransactions = () => {
    try {
        fs.writeFileSync(TRANSACTIONS_FILE, JSON.stringify(transactions, null, 2));
    } catch (error) {
        console.error('Error saving transactions:', error);
    }
};

loadData();

const generateSessionToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

const rateLimit = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, []);
    }
    
    const requests = requestCounts.get(ip).filter(time => now - time < 60000);
    requests.push(now);
    requestCounts.set(ip, requests);
    
    if (requests.length > 100) {
        logSuspiciousActivity(ip, 'RATE_LIMIT_EXCEEDED', req.path);
        return res.status(429).json({ error: 'Too many requests' });
    }
    
    next();
};

const validateSession = (req, res, next) => {
    const token = req.headers['x-session-token'];
    
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const session = activeSessions.get(token);
    if (!session || Date.now() - session.lastActivity > 3600000) {
        activeSessions.delete(token);
        return res.status(401).json({ error: 'Session expired' });
    }
    
    session.lastActivity = Date.now();
    req.userId = session.userId;
    next();
};

const logSuspiciousActivity = (identifier, type, details) => {
    const key = `${identifier}-${type}`;
    if (!suspiciousActivity.has(key)) {
        suspiciousActivity.set(key, []);
    }
    suspiciousActivity.get(key).push({
        timestamp: Date.now(),
        details
    });
};

const validateTradeRequest = (userId, symbol, quantity, price) => {
    const user = users[userId];
    if (!user) return { valid: false, reason: 'User not found' };
    
    if (typeof quantity !== 'number' || quantity <= 0 || !Number.isInteger(quantity)) {
        logSuspiciousActivity(userId, 'INVALID_QUANTITY', { symbol, quantity });
        return { valid: false, reason: 'Invalid quantity' };
    }
    
    if (typeof price !== 'number' || price <= 0) {
        logSuspiciousActivity(userId, 'INVALID_PRICE', { symbol, price });
        return { valid: false, reason: 'Invalid price' };
    }
    
    const recentTrades = transactions.filter(t => 
        t.userId === userId && 
        Date.now() - t.timestamp < 1000
    );
    
    if (recentTrades.length > 5) {
        logSuspiciousActivity(userId, 'RAPID_TRADING', { count: recentTrades.length });
        return { valid: false, reason: 'Trading too quickly' };
    }
    
    return { valid: true };
};

const fetchStockPrice = async (symbol) => {
    try {
        const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=1m&range=1d`;
        const response = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch stock price');
        }
        
        const data = await response.json();
        const price = data.chart?.result?.[0]?.meta?.regularMarketPrice;
        
        if (!price || price <= 0) {
            throw new Error('Invalid stock price');
        }
        
        return price;
    } catch (error) {
        throw new Error(`Error fetching ${symbol}: ${error.message}`);
    }
};

const fetchStockChart = async (symbol, range = '1d', interval = '5m') => {
    try {
        const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=${interval}&range=${range}`;
        const response = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch chart data');
        }
        
        const data = await response.json();
        const result = data.chart?.result?.[0];
        
        return {
            timestamps: result.timestamp,
            prices: result.indicators?.quote?.[0]?.close || [],
            currentPrice: result.meta?.regularMarketPrice
        };
    } catch (error) {
        throw new Error(`Error fetching chart: ${error.message}`);
    }
};

app.use(rateLimit);

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const userId = crypto.randomBytes(16).toString('hex');
    const normalizedUsername = username.toLowerCase();
    
    if (Object.values(users).some(u => u.username.toLowerCase() === normalizedUsername)) {
        return res.status(409).json({ error: 'Username already exists' });
    }
    
    users[userId] = {
        userId,
        username,
        password: hashPassword(password),
        cash: 0,
        portfolio: {},
        tutorialStep: 0,
        tutorialCompleted: false,
        uiTutorialCompleted: false,
        createdAt: Date.now(),
        lastActivity: Date.now()
    };
    
    saveUsers();
    
    const token = generateSessionToken();
    activeSessions.set(token, { userId, lastActivity: Date.now() });
    
    res.json({ 
        token, 
        userId,
        username,
        cash: users[userId].cash,
        tutorialStep: 0,
        tutorialCompleted: false,
        uiTutorialCompleted: false
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    const normalizedUsername = username.toLowerCase();
    const user = Object.values(users).find(u => 
        u.username.toLowerCase() === normalizedUsername
    );
    
    if (!user || user.password !== hashPassword(password)) {
        logSuspiciousActivity(req.ip, 'FAILED_LOGIN', username);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateSessionToken();
    activeSessions.set(token, { userId: user.userId, lastActivity: Date.now() });
    
    user.lastActivity = Date.now();
    saveUsers();
    
    res.json({ 
        token,
        userId: user.userId,
        username: user.username,
        cash: user.cash,
        portfolio: user.portfolio,
        tutorialStep: user.tutorialStep || 0,
        tutorialCompleted: user.tutorialCompleted || false,
        uiTutorialCompleted: user.uiTutorialCompleted || false
    });
});

app.get('/api/portfolio', validateSession, (req, res) => {
    const user = users[req.userId];
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
        cash: user.cash,
        portfolio: user.portfolio,
        username: user.username,
        tutorialStep: user.tutorialStep || 0,
        tutorialCompleted: user.tutorialCompleted || false,
        uiTutorialCompleted: user.uiTutorialCompleted || false
    });
});

app.get('/api/tutorial/current', validateSession, (req, res) => {
    const user = users[req.userId];
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const step = user.tutorialStep || 0;
    
    if (step >= TUTORIAL_LESSONS.length) {
        return res.json({
            completed: true,
            tutorialCompleted: user.tutorialCompleted || false,
            uiTutorialCompleted: user.uiTutorialCompleted || false
        });
    }
    
    const lesson = TUTORIAL_LESSONS[step];
    res.json({
        step,
        total: TUTORIAL_LESSONS.length,
        lesson: {
            id: lesson.id,
            title: lesson.title,
            content: lesson.content,
            question: lesson.question,
            options: lesson.options
        },
        tutorialCompleted: user.tutorialCompleted || false,
        uiTutorialCompleted: user.uiTutorialCompleted || false
    });
});

app.post('/api/tutorial/answer', validateSession, (req, res) => {
    const { answerIndex } = req.body;
    const user = users[req.userId];
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const step = user.tutorialStep || 0;
    
    if (step >= TUTORIAL_LESSONS.length) {
        return res.json({ completed: true });
    }
    
    const lesson = TUTORIAL_LESSONS[step];
    const correct = answerIndex === lesson.correctAnswer;
    
    if (!correct) {
        return res.json({
            correct: false,
            message: 'Not quite right. Please try again!'
        });
    }
    
    user.tutorialStep = step + 1;
    
    if (user.tutorialStep >= TUTORIAL_LESSONS.length) {
        user.tutorialCompleted = true;
        user.cash = 100000;
        saveUsers();
        return res.json({
            correct: true,
            completed: true,
            message: 'Congratulations! You\'ve completed the financial education tutorial. You\'ve been awarded $100,000 to start trading!',
            cash: user.cash
        });
    }
    
    saveUsers();
    res.json({
        correct: true,
        nextStep: user.tutorialStep,
        message: 'Correct! Moving to the next lesson.'
    });
});

app.post('/api/tutorial/ui-complete', validateSession, (req, res) => {
    const user = users[req.userId];
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    user.uiTutorialCompleted = true;
    saveUsers();
    
    res.json({ success: true });
});

app.post('/api/buy', validateSession, async (req, res) => {
    const { symbol, quantity } = req.body;
    const userId = req.userId;
    
    if (!symbol || !quantity) {
        return res.status(400).json({ error: 'Symbol and quantity required' });
    }
    
    try {
        const price = await fetchStockPrice(symbol.toUpperCase());
        const validation = validateTradeRequest(userId, symbol, quantity, price);
        
        if (!validation.valid) {
            return res.status(400).json({ error: validation.reason });
        }
        
        const cost = price * quantity;
        const user = users[userId];
        
        if (user.cash < cost) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }
        
        user.cash -= cost;
        
        if (!user.portfolio[symbol]) {
            user.portfolio[symbol] = { quantity: 0, avgPrice: 0 };
        }
        
        const currentHolding = user.portfolio[symbol];
        const totalShares = currentHolding.quantity + quantity;
        const totalCost = (currentHolding.avgPrice * currentHolding.quantity) + cost;
        
        user.portfolio[symbol] = {
            quantity: totalShares,
            avgPrice: totalCost / totalShares
        };
        
        transactions.push({
            userId,
            type: 'BUY',
            symbol,
            quantity,
            price,
            timestamp: Date.now()
        });
        
        saveUsers();
        saveTransactions();
        
        res.json({
            success: true,
            cash: user.cash,
            portfolio: user.portfolio
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/sell', validateSession, async (req, res) => {
    const { symbol, quantity } = req.body;
    const userId = req.userId;
    
    if (!symbol || !quantity) {
        return res.status(400).json({ error: 'Symbol and quantity required' });
    }
    
    try {
        const price = await fetchStockPrice(symbol.toUpperCase());
        const validation = validateTradeRequest(userId, symbol, quantity, price);
        
        if (!validation.valid) {
            return res.status(400).json({ error: validation.reason });
        }
        
        const user = users[userId];
        const holding = user.portfolio[symbol];
        
        if (!holding || holding.quantity < quantity) {
            return res.status(400).json({ error: 'Insufficient shares' });
        }
        
        const proceeds = price * quantity;
        user.cash += proceeds;
        
        holding.quantity -= quantity;
        
        if (holding.quantity === 0) {
            delete user.portfolio[symbol];
        }
        
        transactions.push({
            userId,
            type: 'SELL',
            symbol,
            quantity,
            price,
            timestamp: Date.now()
        });
        
        saveUsers();
        saveTransactions();
        
        res.json({
            success: true,
            cash: user.cash,
            portfolio: user.portfolio
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/stock/:symbol', async (req, res) => {
    const { symbol } = req.params;
    const { range = '1d', interval = '5m' } = req.query;
    
    try {
        const data = await fetchStockChart(symbol.toUpperCase(), range, interval);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/leaderboard', async (req, res) => {
    const leaderboard = [];
    
    for (const userId in users) {
        const user = users[userId];
        let totalValue = user.cash;
        
        for (const symbol in user.portfolio) {
            try {
                const price = await fetchStockPrice(symbol);
                totalValue += price * user.portfolio[symbol].quantity;
            } catch (error) {
                console.error(`Error fetching ${symbol}:`, error);
            }
        }
        
        leaderboard.push({
            username: user.username,
            totalValue,
            cash: user.cash,
            portfolioValue: totalValue - user.cash
        });
    }
    
    leaderboard.sort((a, b) => b.totalValue - a.totalValue);
    
    res.json(leaderboard.slice(0, 100));
});

app.get('/api/transactions', validateSession, (req, res) => {
    const userId = req.userId;
    const userTransactions = transactions
        .filter(t => t.userId === userId)
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 100);
    
    res.json(userTransactions);
});

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stock Trading Simulator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #000;
            color: #fff;
        }

        .login-container {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
        }

        .login-box {
            background: #1c1c1e;
            padding: 48px 40px;
            border-radius: 16px;
            width: 400px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }

        .logo {
            text-align: center;
            margin-bottom: 32px;
        }

        .logo h1 {
            font-size: 32px;
            font-weight: 700;
            background: linear-gradient(135deg, #6bbf33 0%, #8ddf55 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .input-group {
            margin-bottom: 20px;
        }

        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            color: #999;
        }

        .input-group input {
            width: 100%;
            padding: 14px 16px;
            background: #2c2c2e;
            border: 1px solid #3a3a3c;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            transition: border-color 0.3s;
        }

        .input-group input:focus {
            outline: none;
            border-color: #6bbf33;
        }

        .btn {
            width: 100%;
            padding: 14px;
            background: #6bbf33;
            color: #000;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
            margin-top: 8px;
        }

        .btn:hover {
            background: #8ddf55;
        }

        .btn-secondary {
            background: #2c2c2e;
            color: #fff;
        }

        .btn-secondary:hover {
            background: #3a3a3c;
        }

        .error-message {
            color: #ff453a;
            font-size: 14px;
            margin-top: 12px;
            text-align: center;
        }

        .app-container {
            display: none;
            min-height: 100vh;
        }

        .header {
            background: #1c1c1e;
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #2c2c2e;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 32px;
        }

        .header-logo {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #6bbf33 0%, #8ddf55 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-tabs {
            display: flex;
            gap: 24px;
        }

        .nav-tab {
            color: #999;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            padding: 8px 0;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }

        .nav-tab:hover, .nav-tab.active {
            color: #fff;
            border-bottom-color: #6bbf33;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .user-info {
            text-align: right;
        }

        .username {
            font-size: 14px;
            color: #fff;
            font-weight: 600;
        }

        .cash-balance {
            font-size: 12px;
            color: #999;
        }

        .logout-btn {
            padding: 8px 16px;
            background: #2c2c2e;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }

        .logout-btn:hover {
            background: #3a3a3c;
        }

        .main-content {
            display: flex;
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
            gap: 24px;
        }

        .content-left {
            flex: 1;
        }

        .content-right {
            width: 350px;
        }

        .card {
            background: #1c1c1e;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .card-title {
            font-size: 20px;
            font-weight: 700;
        }

        .search-box {
            position: relative;
            margin-bottom: 24px;
        }

        .search-input {
            width: 100%;
            padding: 14px 16px;
            background: #2c2c2e;
            border: 1px solid #3a3a3c;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
        }

        .search-input:focus {
            outline: none;
            border-color: #6bbf33;
        }

        .chart-container {
            height: 400px;
            background: #0a0a0a;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }

        .time-range-selector {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            overflow-x: auto;
        }

        .time-btn {
            padding: 8px 16px;
            background: #2c2c2e;
            color: #999;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            white-space: nowrap;
            transition: all 0.3s;
        }

        .time-btn:hover, .time-btn.active {
            background: #6bbf33;
            color: #000;
        }

        .stock-price {
            margin-bottom: 24px;
        }

        .price-large {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .price-change {
            font-size: 18px;
            font-weight: 600;
        }

        .price-change.positive {
            color: #6bbf33;
        }

        .price-change.negative {
            color: #ff453a;
        }

        .trade-panel {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
        }

        .trade-input {
            flex: 1;
            padding: 14px 16px;
            background: #2c2c2e;
            border: 1px solid #3a3a3c;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
        }

        .trade-input:focus {
            outline: none;
            border-color: #6bbf33;
        }

        .trade-btn {
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .trade-btn.buy {
            background: #6bbf33;
            color: #000;
        }

        .trade-btn.buy:hover {
            background: #8ddf55;
        }

        .trade-btn.sell {
            background: #ff453a;
            color: #fff;
        }

        .trade-btn.sell:hover {
            background: #ff6961;
        }

        .portfolio-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: #2c2c2e;
            border-radius: 8px;
            margin-bottom: 12px;
            cursor: pointer;
            transition: background 0.3s;
        }

        .portfolio-item:hover {
            background: #3a3a3c;
        }

        .portfolio-symbol {
            font-size: 16px;
            font-weight: 700;
        }

        .portfolio-quantity {
            font-size: 14px;
            color: #999;
        }

        .portfolio-value {
            text-align: right;
        }

        .portfolio-price {
            font-size: 16px;
            font-weight: 600;
        }

        .portfolio-change {
            font-size: 14px;
            font-weight: 600;
        }

        .leaderboard-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: #2c2c2e;
            border-radius: 8px;
            margin-bottom: 12px;
        }

        .leaderboard-rank {
            font-size: 18px;
            font-weight: 700;
            color: #999;
            width: 40px;
        }

        .leaderboard-user {
            flex: 1;
            font-size: 15px;
            font-weight: 600;
        }

        .leaderboard-value {
            font-size: 16px;
            font-weight: 700;
            color: #6bbf33;
        }

        .transaction-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: #2c2c2e;
            border-radius: 8px;
            margin-bottom: 12px;
        }

        .transaction-type {
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }

        .transaction-type.buy {
            background: rgba(107, 191, 51, 0.18);
            color: #6bbf33;
        }

        .transaction-type.sell {
            background: rgba(255, 69, 58, 0.2);
            color: #ff453a;
        }

        .empty-state {
            text-align: center;
            padding: 48px 24px;
            color: #999;
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        canvas {
            width: 100% !important;
            height: 100% !important;
        }

        @media (max-width: 1024px) {
            .main-content {
                flex-direction: column;
            }

            .content-right {
                width: 100%;
            }
        }

        .loading {
            text-align: center;
            padding: 48px;
            color: #999;
        }

        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #2c2c2e;
            padding: 16px 24px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from {
                transform: translateX(400px);
            }
            to {
                transform: translateX(0);
            }
        }

        .toast.success {
            border-left: 4px solid #6bbf33;
        }

        .toast.error {
            border-left: 4px solid #ff453a;
        }

        .tutorial-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            animation: fadeIn 0.3s ease-out;
        }

        .tutorial-modal {
            background: #1c1c1e;
            border-radius: 16px;
            padding: 40px;
            max-width: 600px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.4s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideUp {
            from {
                transform: translateY(50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }

        .tutorial-title {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
            color: #6bbf33;
        }

        .tutorial-progress {
            font-size: 14px;
            color: #999;
            margin-bottom: 24px;
        }

        .tutorial-content {
            font-size: 16px;
            line-height: 1.6;
            color: #e0e0e0;
            margin-bottom: 32px;
        }

        .quiz-section {
            background: #2c2c2e;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
        }

        .quiz-question {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #fff;
        }

        .quiz-options {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .quiz-option {
            padding: 16px;
            background: #3a3a3c;
            border: 2px solid transparent;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            color: #fff;
            text-align: left;
        }

        .quiz-option:hover {
            border-color: #6bbf33;
            background: #4a4a4c;
        }

        .quiz-option.selected {
            border-color: #6bbf33;
            background: #4a4a4c;
        }

        .quiz-feedback {
            margin-top: 16px;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
            display: none;
        }

        .quiz-feedback.correct {
            background: rgba(107, 191, 51, 0.2);
            color: #6bbf33;
            display: block;
        }

        .quiz-feedback.incorrect {
            background: rgba(255, 69, 58, 0.2);
            color: #ff453a;
            display: block;
        }

        .tutorial-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }

        .tutorial-btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            font-size: 16px;
        }

        .tutorial-btn-primary {
            background: #6bbf33;
            color: #000;
        }

        .tutorial-btn-primary:hover {
            background: #5daa2a;
        }

        .tutorial-btn-primary:disabled {
            background: #3a3a3c;
            color: #666;
            cursor: not-allowed;
        }

        .ui-tutorial-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: none;
            z-index: 9999;
        }

        .ui-tutorial-spotlight {
            position: absolute;
            border: 3px solid #6bbf33;
            border-radius: 8px;
            box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.8);
            pointer-events: none;
            transition: all 0.3s ease-out;
        }

        .ui-tutorial-tooltip {
            position: absolute;
            background: #1c1c1e;
            border: 2px solid #6bbf33;
            border-radius: 12px;
            padding: 24px;
            max-width: 350px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            z-index: 10001;
        }

        .ui-tutorial-tooltip h3 {
            color: #6bbf33;
            margin-bottom: 12px;
            font-size: 20px;
        }

        .ui-tutorial-tooltip p {
            color: #e0e0e0;
            line-height: 1.5;
            margin-bottom: 20px;
        }

        .ui-tutorial-tooltip-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .ui-tutorial-step-indicator {
            color: #999;
            font-size: 14px;
        }

        .ui-tutorial-btn {
            padding: 10px 20px;
            background: #6bbf33;
            color: #000;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .ui-tutorial-btn:hover {
            background: #5daa2a;
        }
    </style>
</head>
<body>
    <!-- Tutorial Overlays -->
    <div id="tutorialOverlay" class="tutorial-overlay">
        <div class="tutorial-modal">
            <div class="tutorial-title" id="tutorialTitle"></div>
            <div class="tutorial-progress" id="tutorialProgress"></div>
            <div class="tutorial-content" id="tutorialContent"></div>
            <div class="quiz-section">
                <div class="quiz-question" id="tutorialQuestion"></div>
                <div class="quiz-options" id="tutorialOptions"></div>
                <div class="quiz-feedback" id="tutorialFeedback"></div>
            </div>
            <div class="tutorial-actions">
                <button class="tutorial-btn tutorial-btn-primary" id="tutorialSubmit" onclick="submitTutorialAnswer()" disabled>Submit Answer</button>
            </div>
        </div>
    </div>

    <div id="uiTutorialOverlay" class="ui-tutorial-overlay">
        <div class="ui-tutorial-spotlight" id="uiTutorialSpotlight"></div>
        <div class="ui-tutorial-tooltip" id="uiTutorialTooltip">
            <h3 id="uiTutorialTitle"></h3>
            <p id="uiTutorialText"></p>
            <div class="ui-tutorial-tooltip-actions">
                <span class="ui-tutorial-step-indicator" id="uiTutorialStep"></span>
                <button class="ui-tutorial-btn" id="uiTutorialNext" onclick="nextUITutorialStep()">Next</button>
            </div>
        </div>
    </div>

    <div id="loginContainer" class="login-container">

        <div class="login-box">
            <div class="logo">
                <h1>StockSim</h1>
            </div>
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" placeholder="Enter username" autocomplete="username">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter password" autocomplete="current-password">
            </div>
            <button class="btn" onclick="login()">Sign In</button>
            <button class="btn btn-secondary" onclick="register()">Create Account</button>
            <div id="errorMessage" class="error-message"></div>
        </div>
    </div>

    <div id="appContainer" class="app-container">
        <div class="header">
            <div class="header-left">
                <div class="header-logo">StockSim</div>
                <nav class="nav-tabs">
                    <a href="#" class="nav-tab active" onclick="showTab('trading')">Trading</a>
                    <a href="#" class="nav-tab" onclick="showTab('portfolio')">Portfolio</a>
                    <a href="#" class="nav-tab" onclick="showTab('leaderboard')">Leaderboard</a>
                    <a href="#" class="nav-tab" onclick="showTab('history')">History</a>
                    <a href="#" class="nav-tab" onclick="showTab('tutorial')">Tutorial</a>
                </nav>
            </div>
            <div class="header-right">
                <div class="user-info">
                    <div class="username" id="headerUsername"></div>
                    <div class="cash-balance" id="headerCash"></div>
                </div>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div> 

        <div class="main-content">
            <div class="content-left">
                <div id="tradingTab" class="tab-content">
                    <div class="search-box">
                        <input type="text" class="search-input" id="symbolSearch" placeholder="Search stocks (e.g., AAPL, TSLA, GOOGL)" onkeypress="if(event.key==='Enter') loadStock()">
                    </div>
                    
                    <div id="stockContent" class="card">
                        <div class="empty-state">
                            <div class="empty-state-icon">📈</div>
                            <p>Search for a stock to start trading</p>
                        </div>
                    </div>
                </div>

                <div id="portfolioTab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Your Portfolio</h2>
                        </div>
                        <div id="portfolioList"></div>
                    </div>
                </div>

                <div id="leaderboardTab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Top Traders</h2>
                        </div>
                        <div id="leaderboardList"></div>
                    </div>
                </div>

                <div id="historyTab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Transaction History</h2>
                        </div>
                        <div id="transactionList"></div>
                    </div>
                </div>

                <div id="tutorialTab" class="tab-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Tutorial</h2>
                        </div>
                        <div id="tutorialContent" style="padding: 16px; color: #ccc; font-size: 15px; line-height: 1.6;">
                            <p>Welcome to StockSim — follow the steps below:</p>
                            <ol>
                                <li>Create an account (top-left).</li>
                                <li>Search a stock symbol (e.g., AAPL) in Trading.</li>
                                <li>Use the Buy/Sell panel to place trades.</li>
                                <li>Check your Portfolio and History to review performance.</li>
                            </ol>
                            <div style="text-align:center; margin-top:16px;">
                                <button class="btn" onclick="startTutorial()">Start Guided Tour</button>
                            </div>
                            <div id="tutorialStep" style="margin-top:16px; display:none;">
                                <div id="tutorialText" style="margin-bottom:12px;"></div>
                                <div style="display:flex; gap:8px; justify-content:center;">
                                    <button class="btn btn-secondary" onclick="prevTutorialStep()">Back</button>
                                    <button class="btn" onclick="nextTutorialStep()">Next</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="content-right">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Account</h3>
                    </div>
                    <div style="font-size: 14px; color: #999; margin-bottom: 8px;">Buying Power</div>
                    <div style="font-size: 32px; font-weight: 700; margin-bottom: 24px;" id="cashDisplay"></div>
                    <div style="font-size: 14px; color: #999; margin-bottom: 8px;">Portfolio Value</div>
                    <div style="font-size: 24px; font-weight: 700;" id="portfolioValue">$0.00</div>
                </div>

                <div class="card" id="quickPortfolio">
                    <div class="card-header">
                        <h3 class="card-title">Holdings</h3>
                    </div>
                    <div id="quickPortfolioList"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        let sessionToken = null;
        let currentUserId = null;
        let currentUsername = null;
        let currentCash = 0;
        let currentPortfolio = {};
        let currentSymbol = null;
        let chartInstance = null;
        let currentRange = '1d';

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = \`toast \${type}\`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function formatCurrency(value) {
            return new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: 'USD',
                minimumFractionDigits: 2
            }).format(value);
        }

        function formatNumber(value) {
            return new Intl.NumberFormat('en-US').format(value);
        }

        async function register() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('errorMessage');

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (response.ok) {
                    sessionToken = data.token;
                    currentUserId = data.userId;
                    currentUsername = data.username;
                    currentCash = data.cash;
                    showApp();
                } else {
                    errorEl.textContent = data.error;
                }
            } catch (error) {
                errorEl.textContent = 'Connection error';
            }
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('errorMessage');

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (response.ok) {
                    sessionToken = data.token;
                    currentUserId = data.userId;
                    currentUsername = data.username;
                    currentCash = data.cash;
                    currentPortfolio = data.portfolio;
                    showApp();
                } else {
                    errorEl.textContent = data.error;
                }
            } catch (error) {
                errorEl.textContent = 'Connection error';
            }
        }

        function logout() {
            sessionToken = null;
            currentUserId = null;
            currentUsername = null;
            currentCash = 0;
            currentPortfolio = {};
            document.getElementById('loginContainer').style.display = 'flex';
            document.getElementById('appContainer').style.display = 'none';
        }

        function showApp() {
            document.getElementById('loginContainer').style.display = 'none';
            document.getElementById('appContainer').style.display = 'block';
            updateHeader();
            refreshPortfolio();
            updateQuickPortfolio();
            checkAndShowTutorial();
        }

        let tutorialState = {
            currentStep: 0,
            selectedAnswer: null,
            completed: false,
            uiCompleted: false
        };

        let uiTutorialState = {
            currentStep: 0,
            steps: [
                {
                    element: '#symbolSearch',
                    title: 'Search for Stocks',
                    text: 'Start by searching for a stock ticker symbol. Try searching for "AAPL" (Apple Inc.).',
                    action: 'type-aapl'
                },
                {
                    element: '#symbolSearch',
                    title: 'Load the Stock',
                    text: 'Press Enter or click outside to load the stock information and chart.',
                    action: 'load-stock'
                },
                {
                    element: '#tradeQuantity',
                    title: 'Enter Quantity',
                    text: 'Enter the number of shares you want to buy. Try entering "10".',
                    action: 'enter-quantity'
                },
                {
                    element: '.trade-btn.buy',
                    title: 'Execute Your Trade',
                    text: 'Click the "Buy" button to purchase the shares. Your portfolio will be updated automatically.',
                    action: 'click-buy'
                },
                {
                    element: '.header-right',
                    title: 'Track Your Progress',
                    text: 'Your cash balance and portfolio are displayed here. Check the Portfolio tab to see your holdings!',
                    action: 'complete'
                }
            ]
        };

        async function checkAndShowTutorial() {
            try {
                const response = await fetch('/api/tutorial/current', {
                    headers: { 'X-Session-Token': sessionToken }
                });
                const data = await response.json();

                if (data.completed && data.tutorialCompleted) {
                    tutorialState.completed = true;
                    tutorialState.uiCompleted = data.uiTutorialCompleted || false;
                    
                    if (!tutorialState.uiCompleted) {
                        setTimeout(() => startUITutorial(), 1000);
                    }
                } else if (!data.completed) {
                    showTutorial(data);
                }
            } catch (error) {
                console.error('Error checking tutorial:', error);
            }
        }

        function showTutorial(data) {
            const overlay = document.getElementById('tutorialOverlay');
            const { step, total, lesson } = data;

            tutorialState.currentStep = step;
            tutorialState.selectedAnswer = null;

            document.getElementById('tutorialTitle').textContent = lesson.title;
            document.getElementById('tutorialProgress').textContent = \`Step \${step + 1} of \${total}\`;
            document.getElementById('tutorialContent').textContent = lesson.content;
            document.getElementById('tutorialQuestion').textContent = lesson.question;

            const optionsContainer = document.getElementById('tutorialOptions');
            optionsContainer.innerHTML = '';

            lesson.options.forEach((option, index) => {
                const optionDiv = document.createElement('div');
                optionDiv.className = 'quiz-option';
                optionDiv.textContent = option;
                optionDiv.onclick = () => selectTutorialOption(index);
                optionsContainer.appendChild(optionDiv);
            });

            document.getElementById('tutorialFeedback').style.display = 'none';
            document.getElementById('tutorialSubmit').disabled = true;

            overlay.style.display = 'flex';
        }

        function selectTutorialOption(index) {
            tutorialState.selectedAnswer = index;

            document.querySelectorAll('.quiz-option').forEach((opt, i) => {
                opt.classList.toggle('selected', i === index);
            });

            document.getElementById('tutorialSubmit').disabled = false;
        }

        async function submitTutorialAnswer() {
            if (tutorialState.selectedAnswer === null) return;

            const submitBtn = document.getElementById('tutorialSubmit');
            submitBtn.disabled = true;

            try {
                const response = await fetch('/api/tutorial/answer', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-Token': sessionToken
                    },
                    body: JSON.stringify({ answerIndex: tutorialState.selectedAnswer })
                });

                const data = await response.json();
                const feedback = document.getElementById('tutorialFeedback');

                if (data.correct) {
                    feedback.className = 'quiz-feedback correct'; //tells the user directly what they got correct or wrong
                    feedback.textContent = data.message;
                    feedback.style.display = 'block';

                    if (data.completed) {
                        currentCash = data.cash;
                        updateHeader();
                        setTimeout(() => {
                            document.getElementById('tutorialOverlay').style.display = 'none';
                            showToast(data.message, 'success');
                            setTimeout(() => startUITutorial(), 1000);
                        }, 2000);
                    } else {
                        setTimeout(async () => {
                            const nextResponse = await fetch('/api/tutorial/current', {
                                headers: { 'X-Session-Token': sessionToken }
                            });
                            const nextData = await nextResponse.json();
                            showTutorial(nextData);
                        }, 1500);
                    }
                } else {
                    feedback.className = 'quiz-feedback incorrect';
                    feedback.textContent = data.message || 'Incorrect — try again.';
                    feedback.style.display = 'block';

                    // Briefly show incorrect feedback, then reset the same question
                    setTimeout(() => {
                        feedback.style.display = 'none';
                        feedback.className = 'quiz-feedback';
                        feedback.textContent = '';

                        tutorialState.selectedAnswer = null;
                        document.querySelectorAll('.quiz-option').forEach(opt => opt.classList.remove('selected'));
                        // Require the user to select again before submitting
                        submitBtn.disabled = true;
                    }, 1500);
                }
            } catch (error) {
                showToast('Error submitting answer', 'error');
                submitBtn.disabled = false;
            }
        }

        function startUITutorial() {
            uiTutorialState.currentStep = 0;
            showUITutorialStep();
        }

        function showUITutorialStep() {
            const step = uiTutorialState.steps[uiTutorialState.currentStep];
            if (!step) return;

            const overlay = document.getElementById('uiTutorialOverlay');
            const spotlight = document.getElementById('uiTutorialSpotlight');
            const tooltip = document.getElementById('uiTutorialTooltip');

            const targetElement = document.querySelector(step.element);
            if (!targetElement) {
                nextUITutorialStep();
                return;
            }

            const rect = targetElement.getBoundingClientRect();

            spotlight.style.left = (rect.left - 10) + 'px';
            spotlight.style.top = (rect.top - 10) + 'px';
            spotlight.style.width = (rect.width + 20) + 'px';
            spotlight.style.height = (rect.height + 20) + 'px';

            tooltip.style.left = (rect.left + rect.width / 2 - 175) + 'px';
            tooltip.style.top = (rect.bottom + 20) + 'px';

            document.getElementById('uiTutorialTitle').textContent = step.title;
            document.getElementById('uiTutorialText').textContent = step.text;
            document.getElementById('uiTutorialStep').textContent = \`Step \${uiTutorialState.currentStep + 1} of \${uiTutorialState.steps.length}\`;

            overlay.style.display = 'block';
        }

        function nextUITutorialStep() {
            uiTutorialState.currentStep++;

            if (uiTutorialState.currentStep >= uiTutorialState.steps.length) {
                document.getElementById('uiTutorialOverlay').style.display = 'none';
                
                fetch('/api/tutorial/ui-complete', {
                    method: 'POST',
                    headers: { 'X-Session-Token': sessionToken }
                });

                showToast('UI Tutorial completed! You\\'re all set to start trading.', 'success');
            } else {
                showUITutorialStep();
            }
        }


        function updateHeader() {
            document.getElementById('headerUsername').textContent = currentUsername;
            document.getElementById('headerCash').textContent = formatCurrency(currentCash);
            document.getElementById('cashDisplay').textContent = formatCurrency(currentCash);
        }

        async function refreshPortfolio() {
            try {
                const response = await fetch('/api/portfolio', {
                    headers: { 'X-Session-Token': sessionToken }
                });

                if (response.ok) {
                    const data = await response.json();
                    currentCash = data.cash;
                    currentPortfolio = data.portfolio;
                    updateHeader();
                    updateQuickPortfolio();
                } else {
                    logout();
                }
            } catch (error) {
                console.error('Error refreshing portfolio:', error);
            }
        }

        async function updateQuickPortfolio() {
            const container = document.getElementById('quickPortfolioList');
            
            if (Object.keys(currentPortfolio).length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No holdings yet</p></div>';
                document.getElementById('portfolioValue').textContent = formatCurrency(0);
                return;
            }

            let totalValue = 0;
            let html = '';

            for (const symbol in currentPortfolio) {
                const holding = currentPortfolio[symbol];
                try {
                    const response = await fetch(\`/api/stock/\${symbol}?range=1d&interval=5m\`);
                    const data = await response.json();
                    const currentPrice = data.currentPrice;
                    const value = currentPrice * holding.quantity;
                    const change = ((currentPrice - holding.avgPrice) / holding.avgPrice * 100).toFixed(2);
                    const changeClass = change >= 0 ? 'positive' : 'negative';

                    totalValue += value;

                    html += \`
                        <div class="portfolio-item" onclick="loadStockFromPortfolio('\${symbol}')">
                            <div>
                                <div class="portfolio-symbol">\${symbol}</div>
                                <div class="portfolio-quantity">\${holding.quantity} shares</div>
                            </div>
                            <div class="portfolio-value">
                                <div class="portfolio-price">\${formatCurrency(value)}</div>
                                <div class="portfolio-change \${changeClass}">\${change >= 0 ? '+' : ''}\${change}%</div>
                            </div>
                        </div>
                    \`;
                } catch (error) {
                    console.error(\`Error fetching \${symbol}:\`, error);
                }
            }

            container.innerHTML = html;
            document.getElementById('portfolioValue').textContent = formatCurrency(totalValue);
        }

        function loadStockFromPortfolio(symbol) {
            showTab('trading');
            document.getElementById('symbolSearch').value = symbol;
            loadStock();
        }
        
        async function loadStock() {
            const symbol = document.getElementById('symbolSearch').value.toUpperCase().trim();
            if (!symbol) return;

            currentSymbol = symbol;
            const container = document.getElementById('stockContent');
            container.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const response = await fetch(\`/api/stock/\${symbol}?range=\${currentRange}&interval=\${getInterval()}\`);
                
                if (!response.ok) {
                    throw new Error('Stock not found');
                }

                const data = await response.json();
                renderStockView(symbol, data);
            } catch (error) {
                container.innerHTML = \`
                    <div class="empty-state">
                        <div class="empty-state-icon">⚠️</div>
                        <p>\${error.message}</p>
                    </div>
                \`;
            }
        }

        function getInterval() {
            const intervals = {
                '1d': '5m',
                '1w': '30m',
                '1m': '1d',
                '3m': '1d',
                '1y': '1wk',
                '5y': '1mo'
            };
            return intervals[currentRange] || '1d';
        }

        function renderStockView(symbol, data) {
            const currentPrice = data.currentPrice;
            const prices = data.prices.filter(p => p !== null);
            const firstPrice = prices[0];
            const priceChange = currentPrice - firstPrice;
            const percentChange = ((priceChange / firstPrice) * 100).toFixed(2);
            const changeClass = priceChange >= 0 ? 'positive' : 'negative';

            const holding = currentPortfolio[symbol];
            const ownedShares = holding ? holding.quantity : 0;

            const container = document.getElementById('stockContent');
            container.innerHTML = \`
                <div class="stock-price">
                    <div class="price-large">\${formatCurrency(currentPrice)}</div>
                    <div class="price-change \${changeClass}">
                        \${priceChange >= 0 ? '+' : ''}\${formatCurrency(priceChange)} 
                        (\${percentChange >= 0 ? '+' : ''}\${percentChange}%)
                    </div>
                </div>

                <div class="time-range-selector">
                    <button class="time-btn \${currentRange === '1d' ? 'active' : ''}" onclick="changeRange('1d')">1D</button>
                    <button class="time-btn \${currentRange === '1w' ? 'active' : ''}" onclick="changeRange('1w')">1W</button>
                    <button class="time-btn \${currentRange === '1m' ? 'active' : ''}" onclick="changeRange('1m')">1M</button>
                    <button class="time-btn \${currentRange === '3m' ? 'active' : ''}" onclick="changeRange('3m')">3M</button>
                    <button class="time-btn \${currentRange === '1y' ? 'active' : ''}" onclick="changeRange('1y')">1Y</button>
                    <button class="time-btn \${currentRange === '5y' ? 'active' : ''}" onclick="changeRange('5y')">5Y</button>
                </div>

                <div class="chart-container">
                    <canvas id="stockChart"></canvas>
                </div>

                <div class="trade-panel">
                    <input type="number" class="trade-input" id="tradeQuantity" placeholder="Shares" min="1" step="1">
                    <button class="trade-btn buy" onclick="buyStock()">Buy</button>
                    <button class="trade-btn sell" onclick="sellStock()">Sell</button>
                </div>

                \${ownedShares > 0 ? \`<div style="text-align: center; color: #999; font-size: 14px;">You own \${ownedShares} shares</div>\` : ''}
            \`;

            renderChart(data);
        }

        function renderChart(data) {
            const ctx = document.getElementById('stockChart').getContext('2d');
            
            if (chartInstance) {
                chartInstance.destroy();
            }

            const labels = data.timestamps.map(ts => {
                const date = new Date(ts * 1000);
                if (currentRange === '1d') {
                    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                }
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });

            const prices = data.prices.filter(p => p !== null);
            const color = prices[prices.length - 1] >= prices[0] ? '#6bbf33' : '#ff453a';

            chartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data.prices,
                        borderColor: color,
                        backgroundColor: color + '20',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.1,
                        pointRadius: 0,
                        pointHoverRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: '#2c2c2e',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: '#3a3a3c',
                            borderWidth: 1,
                            callbacks: {
                                label: (context) => formatCurrency(context.parsed.y)
                            }
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            grid: { color: '#2c2c2e' },
                            ticks: { color: '#999', maxTicksLimit: 8 }
                        },
                        y: {
                            display: true,
                            position: 'right',
                            grid: { color: '#2c2c2e' },
                            ticks: {
                                color: '#999',
                                callback: (value) => formatCurrency(value)
                            }
                        }
                    },
                    interaction: {
                        mode: 'index',
                        intersect: false
                    }
                }
            });
        }

        async function changeRange(range) {
            currentRange = range;
            await loadStock();
        }

        async function buyStock() {
            const quantity = parseInt(document.getElementById('tradeQuantity').value);
            
            if (!quantity || quantity <= 0) {
                showToast('Enter a valid quantity', 'error');
                return;
            }

            try {
                const response = await fetch('/api/buy', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-Token': sessionToken
                    },
                    body: JSON.stringify({
                        symbol: currentSymbol,
                        quantity: quantity
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    currentCash = data.cash;
                    currentPortfolio = data.portfolio;
                    updateHeader();
                    updateQuickPortfolio();
                    loadStock();
                    showToast(\`Bought \${quantity} shares of \${currentSymbol}\`);
                    document.getElementById('tradeQuantity').value = '';
                } else {
                    showToast(data.error, 'error');
                }
            } catch (error) {
                showToast('Transaction failed', 'error');
            }
        }

        async function sellStock() {
            const quantity = parseInt(document.getElementById('tradeQuantity').value);
            
            if (!quantity || quantity <= 0) {
                showToast('Enter a valid quantity', 'error');
                return;
            }

            try {
                const response = await fetch('/api/sell', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-Token': sessionToken
                    },
                    body: JSON.stringify({
                        symbol: currentSymbol,
                        quantity: quantity
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    currentCash = data.cash;
                    currentPortfolio = data.portfolio;
                    updateHeader();
                    updateQuickPortfolio();
                    loadStock();
                    showToast(\`Sold \${quantity} shares of \${currentSymbol}\`);
                    document.getElementById('tradeQuantity').value = '';
                } else {
                    showToast(data.error, 'error');
                }
            } catch (error) {
                showToast('Transaction failed', 'error');
            }
        }

        async function showTab(tabName) {
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.style.display = 'none');
            
            event.target.classList.add('active');
            const el = document.getElementById(tabName + 'Tab');
            if (el) el.style.display = 'block';

            if (tabName === 'portfolio') {
                await loadPortfolioTab();
            } else if (tabName === 'leaderboard') {
                await loadLeaderboardTab();
            } else if (tabName === 'history') {
                await loadHistoryTab();
            } else if (tabName === 'tutorial') {
                // tutorial tab is static; UI handled in tutorial functions
            }
        }

        async function loadPortfolioTab() {
            const container = document.getElementById('portfolioList');
            
            if (Object.keys(currentPortfolio).length === 0) {
                container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📊</div><p>Your portfolio is empty</p></div>';
                return;
            }

            container.innerHTML = '<div class="loading">Loading...</div>';

            let html = '';
            let totalValue = currentCash;

            for (const symbol in currentPortfolio) {
                const holding = currentPortfolio[symbol];
                try {
                    const response = await fetch(\`/api/stock/\${symbol}?range=1d&interval=5m\`);
                    const data = await response.json();
                    const currentPrice = data.currentPrice;
                    const value = currentPrice * holding.quantity;
                    const gainLoss = (currentPrice - holding.avgPrice) * holding.quantity;
                    const gainLossPercent = ((currentPrice - holding.avgPrice) / holding.avgPrice * 100).toFixed(2);
                    const changeClass = gainLoss >= 0 ? 'positive' : 'negative';

                    totalValue += value;

                    html += \`
                        <div class="portfolio-item">
                            <div>
                                <div class="portfolio-symbol">\${symbol}</div>
                                <div class="portfolio-quantity">\${holding.quantity} shares @ \${formatCurrency(holding.avgPrice)}</div>
                            </div>
                            <div class="portfolio-value">
                                <div class="portfolio-price">\${formatCurrency(value)}</div>
                                <div class="portfolio-change \${changeClass}">
                                    \${gainLoss >= 0 ? '+' : ''}\${formatCurrency(gainLoss)} 
                                    (\${gainLossPercent >= 0 ? '+' : ''}\${gainLossPercent}%)
                                </div>
                            </div>
                        </div>
                    \`;
                } catch (error) {
                    console.error(\`Error fetching \${symbol}:\`, error);
                }
            }

            const totalGainLoss = totalValue - 100000;
            const totalGainLossPercent = ((totalValue - 100000) / 100000 * 100).toFixed(2);
            const changeClass = totalGainLoss >= 0 ? 'positive' : 'negative';

            container.innerHTML = \`
                <div style="padding: 24px; background: #0a0a0a; border-radius: 8px; margin-bottom: 24px;">
                    <div style="font-size: 14px; color: #999; margin-bottom: 8px;">Total Account Value</div>
                    <div style="font-size: 48px; font-weight: 700; margin-bottom: 8px;">\${formatCurrency(totalValue)}</div>
                    <div class="price-change \${changeClass}" style="font-size: 20px;">
                        \${totalGainLoss >= 0 ? '+' : ''}\${formatCurrency(totalGainLoss)} 
                        (\${totalGainLossPercent >= 0 ? '+' : ''}\${totalGainLossPercent}%)
                    </div>
                </div>
                \${html}
            \`;
        }

        async function loadLeaderboardTab() {
            const container = document.getElementById('leaderboardList');
            container.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const response = await fetch('/api/leaderboard');
                const data = await response.json();

                if (data.length === 0) {
                    container.innerHTML = '<div class="empty-state"><p>No traders yet</p></div>';
                    return;
                }

                let html = '';
                data.forEach((user, index) => {
                    html += \`
                        <div class="leaderboard-item">
                            <div class="leaderboard-rank">#\${index + 1}</div>
                            <div class="leaderboard-user">\${user.username}</div>
                            <div class="leaderboard-value">\${formatCurrency(user.totalValue)}</div>
                        </div>
                    \`;
                });

                container.innerHTML = html;
            } catch (error) {
                container.innerHTML = '<div class="empty-state"><p>Error loading leaderboard</p></div>';
            }
        }

        async function loadHistoryTab() { // transact History
            const container = document.getElementById('transactionList');
            container.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const response = await fetch('/api/transactions', {
                    headers: { 'X-Session-Token': sessionToken }
                });
                const data = await response.json();

                if (data.length === 0) {
                    container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div><p>No transactions yet</p></div>';
                    return;
                }

                let html = '';
                data.forEach(transaction => {
                    const date = new Date(transaction.timestamp).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    });

                    html += \`
                        <div class="transaction-item">
                            <div>
                                <span class="transaction-type \${transaction.type.toLowerCase()}">\${transaction.type}</span>
                                <div style="margin-top: 8px; font-weight: 600;">\${transaction.symbol}</div>
                                <div style="font-size: 12px; color: #999;">\${date}</div>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-weight: 600;">\${transaction.quantity} shares</div>
                                <div style="color: #999;">@ \${formatCurrency(transaction.price)}</div>
                                <div style="font-weight: 700; margin-top: 4px;">\${formatCurrency(transaction.quantity * transaction.price)}</div>
                            </div>
                        </div>
                    \`;
                });

                container.innerHTML = html;
            } catch (error) {
                container.innerHTML = '<div class="empty-state"><p>Error loading history</p></div>';
            }
        }

        // Tutorial state
        const tutorialSteps = [
            'Welcome — create an account to get started.',
            'Search a stock symbol using the search box.',
            'Use the Buy button to purchase shares at market price.',
            'Check Portfolio to review holdings and performance.',
            'Open History to see a record of your trades.'
        ];
        let tutorialIndex = 0;

        function startTutorial() {
            tutorialIndex = 0;
            document.getElementById('tutorialStep').style.display = 'block';
            document.getElementById('tutorialText').textContent = tutorialSteps[tutorialIndex];
        }

        function nextTutorialStep() {
            if (tutorialIndex < tutorialSteps.length - 1) tutorialIndex++;
            document.getElementById('tutorialText').textContent = tutorialSteps[tutorialIndex];
        }

        function prevTutorialStep() {
            if (tutorialIndex > 0) tutorialIndex--;
            document.getElementById('tutorialText').textContent = tutorialSteps[tutorialIndex];
        }

        setInterval(() => {
            if (sessionToken) {
                refreshPortfolio();
                if (currentSymbol) {
                    loadStock();
                }
            }
        }, 30000);
    </script>
</body>
</html>
    `);
});

const server = app.listen(PORT, () => {
    console.log('Server running on port ' + PORT);
    console.log('Open http://localhost:' + PORT + ' in your browser');
});

server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Kill the process using the port or set PORT to a different value.`);
    } else {
        console.error('Server error:', err);
    }
    process.exit(1);
});
