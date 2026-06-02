import threading

class ThreadSafeDatabaseManagement:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize_connectionpool()

        return cls._instance
    


    def __initialize_connectionpool(self):
        # Simulate connection pool initialization
        self.connection_pool = "Connection Pool Initialized"

##########################################################

class LoggerSingleton: #normal singleton without thread safety
    _instance = None  # This private variable holds our single master copy

    def __new__(cls):
        # If the box is empty, create the object for the FIRST and ONLY time
        if cls._instance is None:
            print("[System] Allocating unique logger memory space...")
            cls._instance = super().__new__(cls)
            cls._instance.log_file = "app.log"
            
        # If it already exists, blindly return the existing instance
        return cls._instance

# --- Verification Execution ---
logger1 = LoggerSingleton()  # Outputs: [System] Allocating unique logger memory space...
logger2 = LoggerSingleton()  # Silent! No new allocation happens.

# Prove they point to the exact same physical spot in your computer's RAM
print(logger1 is logger2)    # Outputs: True
