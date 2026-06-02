from functools import wraps
import time

def retry(max_attemps=3, delay=1, exceptions=(Exception,)):
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attemp = 0
            while attemp < max_attemps:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attemp += 1

                    if attemp >= max_attemps:
                        raise Exception(f"Function failed after {max_attemps} attempts")
                    time.sleep(delay)   

        return wrapper
    return decorator


def test_retry_decorator():

    @retry(max_attemps=5, delay=2, exceptions=(ValueError,))
    def unreliable_function():
        return True
