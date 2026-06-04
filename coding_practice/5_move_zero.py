def move_zeroes_fast(nums):
    left = 0
    
    # Loop through the array with a reading pointer
    for right in range(len(nums)):
        # If the current number is not zero...
        if nums[right] != 0:
            # Swap the elements at 'right' and 'left'
            nums[left], nums[right] = nums[right], nums[left]
            # Move the left tracking pointer forward
            left += 1
            
    return nums

# Test cases
print(move_zeroes_fast([0, 1, 0, 3, 12]))  # Output: [1, 3, 12, 0, 0]
print(move_zeroes_fast([0]))               # Output: [0]
