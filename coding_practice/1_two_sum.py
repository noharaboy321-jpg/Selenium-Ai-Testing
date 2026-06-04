def two_sum_easy(nums, target):
    # 1. 'i' points to our first number
    for i in range(len(nums)):
        
        # 2. 'j' points to the numbers coming AFTER index 'i'
        for j in range(i + 1, len(nums)):
            
            # 3. Check if they add up to the target
            if nums[i] + nums[j] == target:
                return [i, j] # Found them! Return their positions.      
    return []
# Test it
print(two_sum_easy([2, 7, 11, 15], 9))  # Output: [0, 1] (2 + 7 = 9)
print(two_sum_easy([3, 2, 4], 6))       # Output: [1, 2] (2 + 4 = 6)

def two_sum_optimized(nums, target):
    # Create a dictionary to store numbers and their indices
    seen = {}
    for i,v in enumerate(nums):
        remaining = target - v
        if remaining in seen:
            return [seen[remaining],i]
        seen[v] = i
    return[]        

def two_sum_two_pointers_sorted_array(arr, target):
    left = 0
    right = len(arr) - 1

    while left < right:
        current_sum = arr[left] + arr[right]
        if current_sum == target:
            return [left, right]
        elif current_sum < target:
            left += 1      # need bigger number
        else:
            right -= 1     # need smaller number
    return []