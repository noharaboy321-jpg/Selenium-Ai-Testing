def find_best_trading_days(prices):
    max_profit = 0
    best_buy_day = 0
    best_sell_day = 0
    
    # i is the day we buy
    for i in range(len(prices)):
        # j is the day we sell
        for j in range(i + 1, len(prices)):
            profit = prices[j] - prices[i]
            
            # If we find a higher profit, update our records
            if profit > max_profit:
                max_profit = profit
                best_buy_day = i    # Captures the best time to buy
                best_sell_day = j   # Captures the best time to sell
                
    print(f"Best time to BUY : Day {best_buy_day} (Price: {prices[best_buy_day]})")
    print(f"Best time to SELL: Day {best_sell_day} (Price: {prices[best_sell_day]})")
    print(f"Maximum Profit   : {max_profit}")
    
    return max_profit

# Run the program
find_best_trading_days([7, 1, 5, 3, 6, 4])
