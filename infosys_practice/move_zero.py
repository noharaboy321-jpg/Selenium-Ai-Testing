def move_zeroes_fast(nums):
    write_index = 0
    
    # Loop through the array with a reading pointer
    for i in range(len(nums)):
        # If the current number is not zero...
        if nums[i] != 0:
            # Swap the elements at 'i' and 'write_index'
            nums[write_index], nums[i] = nums[i], nums[write_index]
            # Move the write tracking pointer forward
            write_index += 1
            
    return nums

# Test cases
print(move_zeroes_fast([0, 1, 0, 3, 12]))  # Output: [1, 3, 12, 0, 0]
print(move_zeroes_fast([0]))               # Output: [0]
