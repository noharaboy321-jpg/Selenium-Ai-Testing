def dup(nums):
    seen = set()
    dup = set()
    for num in nums:
        if num in seen:
            dup.add(num)
        else:
            seen.add(num)
            
    # return list(seen)
    return list(dup)
    
print(dup([1, 2, 3, 2, 1, 5, 6, 1]))
        