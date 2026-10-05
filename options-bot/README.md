# optbot: options trading bot for Robinhood

An automated options trader that only places **defined-risk** trades (vertical spreads and
iron condors) on liquid stocks and ETFs. The default profile is *aggressive, efficient,
medium safety*: it sizes up and sells fairly close to the money, but the worst case of
every trade is known before it is placed, and portfolio circuit breakers sit on top.

It runs in **paper mode by default**: real Robinhood market data, simulated fills and cash.

> **Read this first.** No strategy guarantees profit, and this one can lose money. Options
> spreads can lose their full max loss within days. Robinhood has **no official
> stock/options API**: this bot uses the community `robin_stocks` library, which talks to
> Robinhood's private app endpoints. It can break without warning, and automated trading
> through it may violate Robinhood's terms and get your account restricted. Spreads
> require **options level 3** on your Robinhood account. You are responsible for every
> order it places. This is not financial advice.

## The strategy

Each cycle (every 5 minutes during market hours, skipping the first and last 15 minutes),
for every symbol in the universe:

1. **Read the regime.**
   - *Trend*: price vs 20- and 50-day moving averages (up, down, or neutral).
   - *Momentum*: 14-day RSI. Overextended moves (RSI ≥ 75 or ≤ 25) are not chased.
   - *Volatility*: at-the-money implied vol divided by 20-day realized vol. Above 1.10,
     options are "rich" (sell premium). Below 0.90 they are "cheap" (buy premium).
2. **Pick the trade.**

   | Trend   | IV rich                 | IV normal               | IV cheap               |
   |---------|-------------------------|-------------------------|------------------------|
   | Up      | Bull put credit spread  | Bull put credit spread  | Bull call debit spread |
   | Down    | Bear call credit spread | Bear call credit spread | Bear put debit spread  |
   | Neutral | Iron condor             | no trade                | no trade               |

   - Expiration is about 35 DTE (25 to 50 allowed), where time decay is efficient and
     gamma risk is still low.
   - Credit spreads sell the **0.30-delta** strike, with wings about 2% of the stock
     price wide, and only if the credit is at least **25% of the width**.
   - Debit spreads buy around 0.55 delta and sell around 0.30 delta, and only if the
     debit is at most 50% of the width (reward ≥ risk).
   - Symbols with **earnings** before expiration are skipped.
   - Every leg must pass liquidity filters: open interest ≥ 100 and bid/ask ≤ 25% of mid.
3. **Size it.** Contracts = the largest number whose *max loss* fits within all of:
   4% of equity per trade, 35% of equity across all open trades, and buying power.
4. **Execute efficiently.** Limit orders for the whole spread, starting at mid and walking
   toward the natural price in 3 steps. The order is abandoned if the price stops meeting
   the entry rules. No market orders.
5. **Manage exits** (checked before any new entries):

   | Exit       | Credit spreads / condors                            | Debit spreads        |
   |------------|-----------------------------------------------------|----------------------|
   | Profit     | 50% of max profit captured                          | +80% on the debit    |
   | Stop       | loss ≥ 2× credit **or** ≥ 50% of max loss (sooner)  | −50% of the debit    |
   | Time       | 21 DTE (avoid gamma risk near expiry)               | 10 DTE               |

   Stops and time exits are willing to pay the natural price to get out. Profit-taking is
   more patient.

### Why this mix

- **Premium selling is the core.** Implied volatility usually prices in more movement than
  actually happens (the *volatility risk premium*). Selling 30-delta spreads when IV is
  rich, and taking profit at 50%, is one of the more durable retail options edges.
- **Debit spreads cover the case where premium selling has no edge.** When IV is cheap and
  the trend is clear, buying a spread makes defined-risk directional bets cheaply.
- **No naked options, no 0DTE lottery tickets, no martingale.** These blow up accounts.
  "Aggressive" here means sizing and strike choice, never unlimited risk.

### Safety layers ("medium safety")

| Layer                 | Default | Effect                                                   |
|-----------------------|---------|----------------------------------------------------------|
| Per-trade max loss    | 4%      | No single trade can lose more than this                  |
| Total open risk       | 35%     | Worst case if *everything* goes to max loss at once      |
| Max positions         | 8 (1 per symbol) | Diversification across names                    |
| Re-entry cooldown     | 1 day   | No revenge trading right after a stop                    |
| Daily loss limit      | −6%     | No new entries for the rest of the day                   |
| Drawdown kill switch  | −20% from high-water | Halts all new entries until you run `optbot resume` |

Exits keep running while entries are halted.

## Setup

```bash
cd options-bot
python -m venv .venv && source .venv/bin/activate
pip install -e ".[robinhood,dev]"
cp config.example.toml config.toml

export RH_USERNAME='you@example.com'
export RH_PASSWORD='...'
export RH_MFA_SECRET='...'   # TOTP seed shown when you enable an authenticator app in
                             # Robinhood security settings; omit to approve on your phone
```

## Usage

```bash
optbot --config config.toml scan          # what it would trade right now (places nothing)
optbot --config config.toml run --once    # one paper cycle
optbot --config config.toml run           # paper trading loop
optbot --config config.toml status        # positions, closed trades, win rate, P&L
optbot --config config.toml resume        # clear the drawdown kill switch
```

**Going live** needs two deliberate steps: set `mode = "live"` in `config.toml` *and* pass
`--live`:

```bash
optbot --config config.toml run --live
```

Recommended path: paper trade for at least 4 to 6 weeks (20+ closed trades), check
`optbot status`, then go live with `risk_per_trade_pct = 0.02` before stepping up.

## Known limitations

- **Robinhood API risk** (see above). If `robin_stocks` breaks, the bot logs errors and
  retries each cycle. It does not fail open.
- **The bot trusts its own journal** (`optbot.sqlite3`) for positions. It does not
  reconcile against Robinhood. Don't manually trade the same spreads in the same
  account, and if the process dies mid-order, check the Robinhood app.
- **Partial fills** on entry are journaled at the filled quantity. On exit, the unfilled
  rest stays open and is retried next cycle.
- **Fills are recorded at the limit price.** Real fills can only be equal or better.
- **No historical backtest.** Free historical option chain data doesn't exist. Paper mode
  is the validation path. Paper fills require a 25% concession from mid toward natural
  to keep results honest.
- **Early assignment** on a short leg (rare before 21 DTE, more likely around
  ex-dividend dates) is not handled automatically. Robinhood will notify you.

## Code map

| File                         | What it does                                   |
|------------------------------|------------------------------------------------|
| `optbot/config.py`           | Every tunable, with the defaults above         |
| `optbot/indicators.py`       | SMA, RSI, realized volatility, trend           |
| `optbot/strategies.py`       | Regime → spread selection and strike picking   |
| `optbot/risk.py`             | Sizing, circuit breakers, exit rules           |
| `optbot/engine.py`           | The loop and the limit-order price ladder      |
| `optbot/journal.py`          | SQLite record of positions and risk state      |
| `optbot/brokers/robinhood.py`| Robinhood adapter (`robin_stocks`)             |
| `optbot/brokers/paper.py`    | Paper broker on live data                      |

Tests (`pytest`) run the full loop against a simulated Black-Scholes market, plus the
Robinhood adapter against a mocked API. No account is needed.
