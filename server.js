const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_DURATION = 30 * 24 * 60 * 60 * 1000;

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

    // Check in-memory active sessions first
    let session = activeSessions.get(token);

    if (session) {
        // session expiry handled via expires if present, and short inactivity expiry (1 hour)
        const now = Date.now();
        if ((session.expires && now > session.expires) || (now - session.lastActivity > 3600000)) {
            activeSessions.delete(token);
            session = null;
        } else {
            session.lastActivity = now;
            req.userId = session.userId;
            return next();
        }
    }

    // Fallback: look for persistent token in stored users
    const userWithToken = Object.values(users).find(u => Array.isArray(u.persistentSessions) && u.persistentSessions.some(s => s.token === token && s.expires > Date.now()));
    if (userWithToken) {
        // restore into activeSessions for quicker checks
        const sess = userWithToken.persistentSessions.find(s => s.token === token);
        activeSessions.set(token, { userId: userWithToken.userId, lastActivity: Date.now(), expires: sess.expires });
        req.userId = userWithToken.userId;
        return next();
    }

    return res.status(401).json({ error: 'Session expired or invalid' });
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
        persistentSessions: [],
        createdAt: Date.now(),
        lastActivity: Date.now()
    };
    
    saveUsers();
    
    const token = generateSessionToken();
    activeSessions.set(token, { userId, lastActivity: Date.now(), expires: Date.now() + SESSION_DURATION });
    // persist token so users stay logged in across restarts
    users[userId].persistentSessions = users[userId].persistentSessions || [];
    users[userId].persistentSessions.push({ token, expires: Date.now() + SESSION_DURATION });
    
    res.json({ 
        token, 
        userId,
        username,
        cash: users[userId].cash,
        tutorialStep: 0,
        tutorialCompleted: false,
        uiTutorialCompleted: false,
        sessionExpires: Date.now() + SESSION_DURATION
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
    activeSessions.set(token, { userId: user.userId, lastActivity: Date.now(), expires: Date.now() + SESSION_DURATION });

    // store persistent session on user so token survives server restart
    user.persistentSessions = user.persistentSessions || [];
    user.persistentSessions.push({ token, expires: Date.now() + SESSION_DURATION });

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
        uiTutorialCompleted: user.uiTutorialCompleted || false,
        sessionExpires: Date.now() + SESSION_DURATION
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

// Logout endpoint: remove session token both in-memory and from user's persistent sessions
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-session-token'];
    if (!token) return res.status(400).json({ error: 'No token provided' });

    activeSessions.delete(token);

    // remove from any user's persistentSessions
    for (const userId in users) {
        const user = users[userId];
        if (Array.isArray(user.persistentSessions)) {
            const idx = user.persistentSessions.findIndex(s => s.token === token);
            if (idx !== -1) {
                user.persistentSessions.splice(idx, 1);
                saveUsers();
                break;
            }
        }
    }

    res.json({ success: true });
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

const renderAuthPage = (mode) => {
    const isLogin = mode === 'login';
    const pageTitle = isLogin ? 'Sign In to StockSim' : 'Create your StockSim account';
    const primaryAction = isLogin ? 'Sign In' : 'Create Account';
    const secondaryText = isLogin ? "Don't have an account yet?" : 'Already trading with StockSim?';
    const secondaryLinkText = isLogin ? 'Create one' : 'Sign in';
    const secondaryHref = isLogin ? '/register' : '/login';
    const apiPath = isLogin ? '/api/login' : '/api/register';

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${primaryAction} | StockSim</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: radial-gradient(circle at top, #1c1c1e, #050505 60%);
            color: #fff;
            min-height: 100vh;
        }
        .auth-wrapper {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .auth-card {
            width: 100%;
            max-width: 420px;
            background: rgba(18, 18, 20, 0.9);
            border-radius: 20px;
            padding: 48px 40px;
            box-shadow: 0 30px 70px rgba(0, 0, 0, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .auth-card h1 {
            margin-bottom: 12px;
            font-size: 36px;
        }
        .auth-card p {
            margin-bottom: 32px;
            color: #bfbfbf;
            line-height: 1.5;
        }
        .input-group {
            margin-bottom: 18px;
        }
        .input-group label {
            display: block;
            font-size: 13px;
            color: #9ca3af;
            margin-bottom: 6px;
        }
        .input-group input {
            width: 100%;
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid #2c2c2e;
            background: #0c0c0e;
            color: #fff;
            font-size: 16px;
            transition: border-color 0.2s ease;
        }
        .input-group input:focus {
            outline: none;
            border-color: #6bbf33;
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            background: linear-gradient(135deg, #6bbf33, #8ddf55);
            color: #000;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 12px 30px rgba(107, 191, 51, 0.35);
        }
        .switch-line {
            margin-top: 18px;
            text-align: center;
            color: #8a8a8a;
            font-size: 14px;
        }
        .switch-line a {
            color: #6bbf33;
            text-decoration: none;
        }
        .error-message {
            margin-top: 18px;
            font-size: 14px;
            color: #ff6b6b;
            min-height: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="auth-wrapper">
        <div class="auth-card">
            <h1>StockSim</h1>
            <p>${pageTitle}. Trade with live data and friendly insights.</p>
            <div class="input-group">
                <label for="username">Username</label>
                <input id="username" type="text" placeholder="Choose a username" autocomplete="username">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input id="password" type="password" placeholder="Create a password" autocomplete="current-password">
            </div>
            <button id="authButton" class="btn" type="button" onclick="submitAuth()">${primaryAction}</button>
            <div class="switch-line">
                ${secondaryText} <a href="${secondaryHref}">${secondaryLinkText}</a>
            </div>
            <div id="errorMessage" class="error-message"></div>
        </div>
    </div>
    <script>
        async function submitAuth() {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('errorMessage');
            errorEl.textContent = '';

            if (!username || !password) {
                errorEl.textContent = 'Username and password are required.';
                return;
            }

            try {
                const response = await fetch('${apiPath}', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();

                if (response.ok) {
                    localStorage.setItem('sessionToken', data.token);
                    window.location.href = '/';
                } else {
                    errorEl.textContent = data.error || 'Authentication failed.';
                }
            } catch (error) {
                errorEl.textContent = 'Unable to reach the server.';
            }
        }

        document.getElementById('password').addEventListener('keypress', (event) => {
            if (event.key === 'Enter') submitAuth();
        });
    </script>
</body>
</html>`;
};

app.get('/login', (req, res) => {
    res.send(renderAuthPage('login'));
});

app.get('/register', (req, res) => {
    res.send(renderAuthPage('register'));
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

    <div id="appContainer" class="app-container">
        <div class="header">
            <div class="header-left">
                <div class="header-logo">StockSim</div>
                <nav class="nav-tabs">
                    <a href="#" class="nav-tab active" data-tab="trading" onclick="showTab(event, 'trading')">Trading</a>
                    <a href="#" class="nav-tab" data-tab="portfolio" onclick="showTab(event, 'portfolio')">Portfolio</a>
                    <a href="#" class="nav-tab" data-tab="leaderboard" onclick="showTab(event, 'leaderboard')">Leaderboard</a>
                    <a href="#" class="nav-tab" data-tab="history" onclick="showTab(event, 'history')">History</a>
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
        let currentUsername = null;
        let currentCash = 0;
        let currentPortfolio = {};
        let currentSymbol = null;
        let chartInstance = null;
        let currentRange = '1d';

        document.addEventListener('DOMContentLoaded', initApp);

        async function initApp() {
            const storedToken = localStorage.getItem('sessionToken');
            if (!storedToken) {
                window.location.href = '/login';
                return;
            }

            sessionToken = storedToken;

            try {
                const response = await fetch('/api/portfolio', {
                    headers: { 'X-Session-Token': sessionToken }
                });

                if (!response.ok) {
                    throw new Error('Session expired');
                }

                const data = await response.json();
                currentCash = data.cash;
                currentPortfolio = data.portfolio;
                currentUsername = data.username;
                document.getElementById('appContainer').style.display = 'block';
                showApp();
            } catch (error) {
                localStorage.removeItem('sessionToken');
                window.location.href = '/login';
            }
        }

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

        function logout() {
            sessionToken = null;
            currentUsername = null;
            currentCash = 0;
            currentPortfolio = {};
            localStorage.removeItem('sessionToken');
            window.location.href = '/login';
        }

        function showApp() {
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
                    text: 'Start by searching for a stock ticker symbol. Try typing "AAPL" (Apple Inc.).',
                    action: 'type-aapl'
                },
                {
                    element: '#symbolSearch',
                    title: 'Load the Stock',
                    text: 'Press Enter to load the stock information and chart.',
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
                    text: 'Click the "Buy" button to place your order. The tutorial will continue once the buy succeeds.',
                    action: 'click-buy'
                },
                {
                    element: '.header-right',
                    title: 'View Portfolio',
                    text: 'Great — your trade completed. Check your Portfolio to review holdings and performance.',
                    action: 'view-portfolio'
                }
            ],
            // runtime flags
            waitingForBuy: false,
            listeners: {}
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

            const rect = targetElement.getBoundingClientRect();
            const scrollX = window.scrollX || window.pageXOffset || 0;
            const scrollY = window.scrollY || window.pageYOffset || 0;

            spotlight.style.left = (rect.left + scrollX - 10) + 'px';
            spotlight.style.top = (rect.top + scrollY - 10) + 'px';
            spotlight.style.width = (rect.width + 20) + 'px';
            spotlight.style.height = (rect.height + 20) + 'px';

            tooltip.style.left = (rect.left + scrollX + rect.width / 2 - 175) + 'px';
            tooltip.style.top = (rect.bottom + scrollY + 20) + 'px';
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
            const scrollX = window.scrollX || window.pageXOffset || 0;
            const scrollY = window.scrollY || window.pageYOffset || 0;

            spotlight.style.left = (rect.left + scrollX - 10) + 'px';
            spotlight.style.top = (rect.top + scrollY - 10) + 'px';
            spotlight.style.width = (rect.width + 20) + 'px';
            spotlight.style.height = (rect.height + 20) + 'px';

            tooltip.style.left = (rect.left + scrollX + rect.width / 2 - 175) + 'px';
            tooltip.style.top = (rect.bottom + scrollY + 20) + 'px';

            document.getElementById('uiTutorialTitle').textContent = step.title;
            document.getElementById('uiTutorialText').textContent = step.text;
            document.getElementById('uiTutorialStep').textContent = \`Step \${uiTutorialState.currentStep + 1} of \${uiTutorialState.steps.length}\`;

            overlay.style.display = 'block';

            // attach action listeners depending on the step
            // remove any previous listeners first
            try { detachUITutorialListeners(); } catch (e) {}

            if (step.action === 'type-aapl') {
                const input = document.getElementById('symbolSearch');
                const handler = (e) => {
                    if (input.value.trim().toUpperCase() === 'AAPL') {
                        input.removeEventListener('input', handler);
                        nextUITutorialStep();
                    }
                };
                uiTutorialState.listeners.typeAapl = handler;
                input.addEventListener('input', handler);
            } else if (step.action === 'load-stock') {
                // poll for currentSymbol to be AAPL (triggered by Enter)
                const interval = setInterval(() => {
                    if (currentSymbol && currentSymbol.toUpperCase() === 'AAPL') {
                        clearInterval(interval);
                        nextUITutorialStep();
                    }
                }, 400);
                uiTutorialState.listeners.loadInterval = interval;
            } else if (step.action === 'enter-quantity') {
                const qty = document.getElementById('tradeQuantity');
                const handler = (e) => {
                    const val = parseInt(qty.value, 10);
                    if (!isNaN(val) && val >= 1) {
                        qty.removeEventListener('input', handler);
                        nextUITutorialStep();
                    }
                };
                uiTutorialState.listeners.enterQty = handler;
                qty.addEventListener('input', handler);
            } else if (step.action === 'click-buy') {
                // set a flag; progression will occur only when buyStock reports success
                uiTutorialState.waitingForBuy = true;
            } else if (step.action === 'view-portfolio') {
                // nothing to attach; user can view portfolio
            }
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

        function detachUITutorialListeners() {
            try {
                if (uiTutorialState.listeners.typeAapl) {
                    const input = document.getElementById('symbolSearch');
                    input.removeEventListener('input', uiTutorialState.listeners.typeAapl);
                    delete uiTutorialState.listeners.typeAapl;
                }
                if (uiTutorialState.listeners.loadInterval) {
                    clearInterval(uiTutorialState.listeners.loadInterval);
                    delete uiTutorialState.listeners.loadInterval;
                }
                if (uiTutorialState.listeners.enterQty) {
                    const qty = document.getElementById('tradeQuantity');
                    qty.removeEventListener('input', uiTutorialState.listeners.enterQty);
                    delete uiTutorialState.listeners.enterQty;
                }
            } catch (e) {
                // ignore
            }
            uiTutorialState.waitingForBuy = false;
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
            showTab(null, 'trading');
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

                    // If the UI tutorial is waiting for a buy action, advance the tutorial
                    try {
                        if (typeof uiTutorialState !== 'undefined' && uiTutorialState.waitingForBuy) {
                            uiTutorialState.waitingForBuy = false;
                            try { detachUITutorialListeners(); } catch (e) {}
                            nextUITutorialStep();
                        }
                    } catch (e) {
                        // ignore if tutorial state not available
                    }
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

        async function showTab(event, tabName) {
            if (event) event.preventDefault();
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.style.display = 'none');
            
            const tabSelector = '.nav-tab[data-tab="' + tabName + '"]';
            const activeTab = event ? event.currentTarget : document.querySelector(tabSelector);
            if (activeTab) activeTab.classList.add('active');

            const el = document.getElementById(tabName + 'Tab');
            if (el) el.style.display = 'block';

            if (tabName === 'portfolio') {
                await loadPortfolioTab();
            } else if (tabName === 'leaderboard') {
                await loadLeaderboardTab();
            } else if (tabName === 'history') {
                await loadHistoryTab();
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
