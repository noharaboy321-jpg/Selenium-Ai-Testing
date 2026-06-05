import time
from multiprocessing import Process, Pool

def heavy_math_calculation(n):
    # Simulated heavy CPU calculation
    return sum(i * i for i in range(n))

if __name__ == "__main__":
    inputs = [10000000, 10000000, 10000000, 10000000]
    # --- THIS BYPASSES THE GIL ---
    # Pool spawns a completely independent Python interpreter process per CPU core.
    # Each process has its own GIL, allowing true simultaneous execution.
    start_time = time.time()
    with Pool() as pool:
        results = pool.map(heavy_math_calculation, inputs)
    
    print(f"Executed parallel calculation across CPU cores in: {time.time() - start_time:.2f} seconds")
    print("Results:", results)  
    