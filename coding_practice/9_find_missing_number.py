def find_missing(nums):
    nums.sort()
    for i in range(len(nums)):
        if nums[i] != i+1:
            return i+1
    return len(nums)+1


###############################3


def find_missing(nums):
    n = len(nums) + 1   # because one number is missing
    expected_sum = n * (n + 1) // 2
    actual_sum = sum(nums)
    return expected_sum - actual_sum

print(find_missing([1,2,3,4,6]))  # Output: 5
