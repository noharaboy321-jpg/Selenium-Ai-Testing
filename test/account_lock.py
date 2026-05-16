@pytest.fixture(scope="function")
def unique_cc_account():
    r = redis.Redis(host='redis-test-data-service.internal', port=6379, db=0)
    
    # ==========================================
    # 1. THE LOCK HAPPENS HERE (Atomic Checkout)
    # ==========================================
    # SPOP removes the item from the pool. No other worker can see it now.
    account_data = r.spop("cc_accounts_pool") 
    
    account_locked = json.loads(account_data.decode('utf-8'))
    
    # The test worker runs safely here with its exclusive data
    yield account_locked 
    
    # ==========================================
    # 2. THE UNLOCK HAPPENS HERE (Check-in)
    # ==========================================
    # SADD pushes the account back into the pool, making it available again.
    r.sadd("cc_accounts_pool", json.dumps(account_locked)) 


@pytest.fixture(scope="function")
def unique_cc_account():
    r = redis.Redis(host='redis-test-data-service.internal', port=6379, db=0)
    
    # Loop through your known account IDs (e.g., user_1 to user_50)
    for i in range(1, 51):
        account_key = f"account_user_{i}"
        lock_key = f"lock:account_user_{i}"
        
        # ==========================================
        # THE LOCK: Try to claim an exclusive lease
        # ==========================================
        # SETNX (set if not exists) only succeeds if the key is empty.
        # ex=300 automatically unlocks the account after 5 mins if the test crashes.
        if r.set(lock_key, "busy", nx=True, ex=300):
            # Lock secured! Fetch the account data.
            account_data = json.loads(r.get(account_key))
            
            yield account_data
            
            # ==========================================
            # THE UNLOCK: Release the lease
            # ==========================================
            r.delete(lock_key)
            return
            
    raise RuntimeError("All accounts are currently locked by other parallel tests!")