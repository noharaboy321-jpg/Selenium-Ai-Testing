def find_max_min_manual(array):
    if not array:
        return None, None  # Handle empty array edge case Safely
        
    # 1. Initialize our tracking values with the first element
    current_max = array[0]
    current_min = array[0]
    
    # 2. Check every number in the array
    for num in array:
        if num > current_max:
            current_max = num  # Found a bigger number! Update max.
        if num < current_min:
            current_min = num  # Found a smaller number! Update min.
            
    return current_max, current_min

# Test the manual function
my_array = [12, 45, 2, 89, 23, -5, 67]
max_num, min_num = find_max_min_manual(my_array)

print(f"Manual Max: {max_num}")
print(f"Manual Min: {min_num}")
