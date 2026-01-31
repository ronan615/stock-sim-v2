        let sessionToken = null;
        let currentUserId = null;
        let currentUsername = null;
        let currentCash = 0;
        let currentPortfolio = {};
        let currentSymbol = null;
        let chartInstance = null;
        let currentRange = '1d';

        function showToast(message, type) {
            type = type || 'success';
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(function() { toast.remove(); }, 3000);
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
                    tutorialStep = data.tutorialStep || 0;
                    tutorialCompleted = data.tutorialCompleted || false;
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
                    tutorialStep = data.tutorialStep || 0;
                    tutorialCompleted = data.tutorialCompleted || false;
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

        let tutorialCompleted = false;
        let tutorialStep = 0;

        const TUTORIAL_DATA = [
            {
                title: "What is a Stock?",
                content: "A stock represents a piece of ownership in a company. When you purchase a share, you are essentially buying a tiny portion of that business. If the company does well, your share may become more valuable.",
                question: "What does owning a stock represent?",
                options: ["A loan to the company", "Ownership in the company", "A guaranteed monthly payment"]
            },
            {
                title: "Supply and Demand",
                content: "Stock prices fluctuate based on the laws of supply and demand. If more people want to buy a stock (demand) than sell it (supply), the price rises. If more people want to sell, the price falls.",
                question: "If demand for a stock increases significantly, what typically happens to the price?",
                options: ["The price goes down", "The price stays the same", "The price goes up"]
            },
            {
                title: "Diversification",
                content: "Diversification is the practice of spreading your investments across different assets to reduce risk. 'Don't put all your eggs in one basket' is the golden rule of investing.",
                question: "Why do investors practice diversification?",
                options: ["To maximize risk", "To reduce the impact of any single stock's failure", "To avoid paying taxes"]
            },
            {
                title: "Risk and Reward",
                content: "Every investment carries risk. Generally, the higher the potential return, the higher the risk. Understanding your risk tolerance is crucial before you start trading real or simulated capital.",
                question: "What is the general relationship between risk and potential reward?",
                options: ["Higher risk usually means higher potential reward", "Lower risk usually means higher potential reward", "There is no relationship"]
            }
        ];

        function showApp() {
            document.getElementById('loginContainer').style.display = 'none';
            document.getElementById('appContainer').style.display = 'block';
            updateHeader();
            refreshPortfolio();
            updateQuickPortfolio();
            checkTutorial();
        }

        function checkTutorial() {
            if (!tutorialCompleted) {
                document.getElementById('tutorialOverlay').style.display = 'flex';
                renderTutorialStep();
            } else {
                document.getElementById('tutorialOverlay').style.display = 'none';
            }
        }

        function renderTutorialStep() {
            const step = TUTORIAL_DATA[tutorialStep];
            if (!step) return;

            const modal = document.getElementById('tutorialModal');
            let optionsHtml = '';
            step.options.forEach((opt, idx) => {
                optionsHtml += '<button class="option-btn" onclick="submitTutorialAnswer(' + idx + ')">' + opt + '</button>';
            });

            modal.innerHTML = 
                '<div class="tutorial-title">' + step.title + '</div>' +
                '<div class="tutorial-text">' + step.content + '</div>' +
                '<div class="quiz-container">' +
                    '<div class="quiz-question">' + step.question + '</div>' +
                    '<div class="options-list">' +
                        optionsHtml +
                    '</div>' +
                '</div>' +
                '<div style="margin-top: 20px; color: #666; font-size: 13px; text-align: center;">' +
                    'Step ' + (tutorialStep + 1) + ' of ' + TUTORIAL_DATA.length +
                '</div>';
        }

        async function submitTutorialAnswer(answerIndex) {
            try {
                const response = await fetch('/api/tutorial/answer', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Session-Token': sessionToken
                    },
                    body: JSON.stringify({ answerIndex })
                });

                const data = await response.json();

                if (response.ok) {
                    if (data.completed) {
                        tutorialCompleted = true;
                        currentCash = data.cash;
                        showToast(data.message || 'Tutorial completed!', 'success');
                        checkTutorial();
                        updateHeader();
                    } else {
                        tutorialStep = data.nextStep;
                        renderTutorialStep();
                    }
                } else {
                    showToast(data.error, 'error');
                }
            } catch (error) {
                showToast('Connection error', 'error');
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
                    tutorialStep = data.tutorialStep || 0;
                    tutorialCompleted = data.tutorialCompleted || false;
                    updateHeader();
                    updateQuickPortfolio();
                    checkTutorial();
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
                    const response = await fetch('/api/stock/' + symbol + '?range=1d&interval=5m');
                    const data = await response.json();
                    const currentPrice = data.currentPrice;
                    const value = currentPrice * holding.quantity;
                    const change = ((currentPrice - holding.avgPrice) / holding.avgPrice * 100).toFixed(2);
                    const changeClass = change >= 0 ? 'positive' : 'negative';

                    totalValue += value;

                    html += 
                        '<div class="portfolio-item" onclick="loadStockFromPortfolio(\'' + symbol + '\')">' +
                            '<div>' +
                                '<div class="portfolio-symbol">' + symbol + '</div>' +
                                '<div class="portfolio-quantity">' + holding.quantity + ' shares</div>' +
                            '</div>' +
                            '<div class="portfolio-value">' +
                                '<div class="portfolio-price">' + formatCurrency(value) + '</div>' +
                                '<div class="portfolio-change ' + changeClass + '">' + (change >= 0 ? '+' : '') + change + '%</div>' +
                            '</div>' +
                        '</div>';
                } catch (error) {
                    console.error('Error fetching ' + symbol + ':', error);
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
                const response = await fetch('/api/stock/' + symbol + '?range=' + currentRange + '&interval=' + getInterval());
                
                if (!response.ok) {
                    throw new Error('Stock not found');
                }

                const data = await response.json();
                renderStockView(symbol, data);
            } catch (error) {
                container.innerHTML = 
                    '<div class="empty-state">' +
                        '<div class="empty-state-icon">⚠️</div>' +
                        '<p>' + error.message + '</p>' +
                    '</div>';
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
            const prices = data.prices.filter(function(p) { return p !== null; });
            const firstPrice = prices[0];
            const priceChange = currentPrice - firstPrice;
            const percentChange = ((priceChange / firstPrice) * 100).toFixed(2);
            const changeClass = priceChange >= 0 ? 'positive' : 'negative';

            const holding = currentPortfolio[symbol];
            const ownedShares = holding ? holding.quantity : 0;

            const container = document.getElementById('stockContent');
            container.innerHTML = 
                '<div class="stock-price">' +
                    '<div class="price-large">' + formatCurrency(currentPrice) + '</div>' +
                    '<div class="price-change ' + changeClass + '">' +
                        (priceChange >= 0 ? '+' : '') + formatCurrency(priceChange) + ' ' +
                        '(' + (percentChange >= 0 ? '+' : '') + percentChange + '%)' +
                    '</div>' +
                '</div>' +

                '<div class="time-range-selector">' +
                    '<button class="time-btn ' + (currentRange === '1d' ? 'active' : '') + '" onclick="changeRange(\'1d\')">1D</button>' +
                    '<button class="time-btn ' + (currentRange === '1w' ? 'active' : '') + '" onclick="changeRange(\'1w\')">1W</button>' +
                    '<button class="time-btn ' + (currentRange === '1m' ? 'active' : '') + '" onclick="changeRange(\'1m\')">1M</button>' +
                    '<button class="time-btn ' + (currentRange === '3m' ? 'active' : '') + '" onclick="changeRange(\'3m\')">3M</button>' +
                    '<button class="time-btn ' + (currentRange === '1y' ? 'active' : '') + '" onclick="changeRange(\'1y\')">1Y</button>' +
                    '<button class="time-btn ' + (currentRange === '5y' ? 'active' : '') + '" onclick="changeRange(\'5y\')">5Y</button>' +
                '</div>' +

                '<div class="chart-container">' +
                    '<canvas id="stockChart"></canvas>' +
                '</div>' +

                '<div class="trade-panel">' +
                    '<input type="number" class="trade-input" id="tradeQuantity" placeholder="Shares" min="1" step="1">' +
                    '<button class="trade-btn buy" onclick="buyStock()">Buy</button>' +
                    '<button class="trade-btn sell" onclick="sellStock()">Sell</button>' +
                '</div>' +

                (ownedShares > 0 ? '<div style="text-align: center; color: #999; font-size: 14px;">You own ' + ownedShares + ' shares</div>' : '');

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
                    showToast('Bought ' + quantity + ' shares of ' + currentSymbol);
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
                    showToast('Sold ' + quantity + ' shares of ' + currentSymbol);
                    document.getElementById('tradeQuantity').value = '';
                } else {
                    showToast(data.error, 'error');
                }
            } catch (error) {
                showToast('Transaction failed', 'error');
            }
        }

        async function showTab(tabName, event) {
            const tabs = document.querySelectorAll('.nav-tab');
            const contents = document.querySelectorAll('.tab-content');
            
            tabs.forEach(tab => tab.classList.remove('active'));
            contents.forEach(content => content.style.display = 'none');
            
            const el = document.getElementById(tabName + 'Tab');
            if (el) el.style.display = 'block';

            // Find the tab button and activate it
            if (event && event.target) {
                event.target.classList.add('active');
            } else {
                tabs.forEach(tab => {
                    if (tab.textContent.toLowerCase() === tabName.toLowerCase()) {
                        tab.classList.add('active');
                    }
                });
            }

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
                    const response = await fetch('/api/stock/' + symbol + '?range=1d&interval=5m');
                    const data = await response.json();
                    const currentPrice = data.currentPrice;
                    const value = currentPrice * holding.quantity;
                    const gainLoss = (currentPrice - holding.avgPrice) * holding.quantity;
                    const gainLossPercent = ((currentPrice - holding.avgPrice) / holding.avgPrice * 100).toFixed(2);
                    const changeClass = gainLoss >= 0 ? 'positive' : 'negative';

                    totalValue += value;

                    html += 
                        '<div class="portfolio-item">' +
                            '<div>' +
                                '<div class="portfolio-symbol">' + symbol + '</div>' +
                                '<div class="portfolio-quantity">' + holding.quantity + ' shares @ ' + formatCurrency(holding.avgPrice) + '</div>' +
                            '</div>' +
                            '<div class="portfolio-value">' +
                                '<div class="portfolio-price">' + formatCurrency(value) + '</div>' +
                                '<div class="portfolio-change ' + changeClass + '">' +
                                    (gainLoss >= 0 ? '+' : '') + formatCurrency(gainLoss) + ' ' +
                                    '(' + (gainLossPercent >= 0 ? '+' : '') + gainLossPercent + '%)' +
                                '</div>' +
                            '</div>' +
                        '</div>';
                } catch (error) {
                    console.error('Error fetching ' + symbol + ':', error);
                }
            }

            const totalGainLoss = totalValue - 100000;
            const totalGainLossPercent = ((totalValue - 100000) / 100000 * 100).toFixed(2);
            const changeClass = totalGainLoss >= 0 ? 'positive' : 'negative';

            container.innerHTML = 
                '<div style="padding: 24px; background: #0a0a0a; border-radius: 8px; margin-bottom: 24px;">' +
                    '<div style="font-size: 14px; color: #999; margin-bottom: 8px;">Total Account Value</div>' +
                    '<div style="font-size: 48px; font-weight: 700; margin-bottom: 8px;">' + formatCurrency(totalValue) + '</div>' +
                    '<div class="price-change ' + changeClass + '" style="font-size: 20px;">' +
                        (totalGainLoss >= 0 ? '+' : '') + formatCurrency(totalGainLoss) + ' ' +
                        '(' + (totalGainLossPercent >= 0 ? '+' : '') + totalGainLossPercent + '%)' +
                    '</div>' +
                '</div>' +
                html;
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
                data.forEach(function(user, index) {
                    html += 
                        '<div class="leaderboard-item">' +
                            '<div class="leaderboard-rank">#' + (index + 1) + '</div>' +
                            '<div class="leaderboard-user">' + user.username + '</div>' +
                            '<div class="leaderboard-value">' + formatCurrency(user.totalValue) + '</div>' +
                        '</div>';
                });

                container.innerHTML = html;
            } catch (error) {
                container.innerHTML = '<div class="empty-state"><p>Error loading leaderboard</p></div>';
            }
        }

        async function loadHistoryTab() {
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
                data.forEach(function(transaction) {
                    const date = new Date(transaction.timestamp).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    });

                    html += 
                        '<div class="transaction-item">' +
                            '<div>' +
                                '<span class="transaction-type ' + transaction.type.toLowerCase() + '">' + transaction.type + '</span>' +
                                '<div style="margin-top: 8px; font-weight: 600;">' + transaction.symbol + '</div>' +
                                '<div style="font-size: 12px; color: #999;">' + date + '</div>' +
                            '</div>' +
                            '<div style="text-align: right;">' +
                                '<div style="font-weight: 600;">' + transaction.quantity + ' shares</div>' +
                                '<div style="color: #999;">@ ' + formatCurrency(transaction.price) + '</div>' +
                                '<div style="font-weight: 700; margin-top: 4px;">' + formatCurrency(transaction.quantity * transaction.price) + '</div>' +
                            '</div>' +
                        '</div>';
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
