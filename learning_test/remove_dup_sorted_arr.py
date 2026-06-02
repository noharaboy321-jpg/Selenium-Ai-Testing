def remove_duplicates(nums):
    # Edge case: If the array is empty, there are 0 unique elements
    if not nums:
        return 0
        
    # The write pointer tracks the position of the last known unique element
    write = 0
    
    # The read pointer scans through the entire array starting from the second element
    for read in range(1, len(nums)):
        # If we find a value that is different from our last unique element
        if nums[read] != nums[write]:
            write += 1             # Move to the next slot
            nums[write] = nums[read]  # Overwrite it with the new unique value
            
    # The number of unique elements is the index position + 1
    return write + 1


# --- Driver Code to Test ---
if __name__ == "__main__":
    test_array = [0, 0, 1, 1, 1, 2, 2, 3, 3, 4]
    print(f"Original Array: {test_array}")
    
    # Call the function
    k = remove_duplicates(test_array)
    
    print(f"Number of unique elements (k): {k}")
    print(f"Modified Array (first k elements): {test_array[:k]}")
