def find_duplicates(nums):
    seen = set()
    dup = set()  # Using a set avoids adding the same duplicate multiple times 
    for num in nums:
        if num in seen:
            dup.add(num)
        else:
            seen.add(num)          
    return list(dup)
print(find_duplicates([4, 3, 2, 7, 8, 2, 3, 1]))  # Output: [2, 3]
#==================================================================================================
from collections import Counter
def find_duplicates_fast(nums):
    # Counter creates a frequency map: {element: count}
    counts = Counter(nums)
    # Return a list of items that appeared more than once
    return [char for char, count in counts.items() if count > 1]
#
print(find_duplicates_fast([1, 2, 3, 1, 2, 4]))  # Output: [1, 2]
#==================================================================================================
def first_uniq_char_easy(s: str) -> int:
    counts = Counter(s)
    # 2. Loop through the string and check the counts
    for index, char in enumerate(s):
        if counts[char] == 1:
            return index  # Return the index of the first unique character   
    return -1  # If no unique character is found
#================###########################################
def frequency_of_char(input_string: str) -> dict:
	
	frequency_map = {}
	
	for char in input_string:
		if char in frequency_map:
			frequency_map[char] += 1
		else:
			frequency_map[char] = 1		
	for key, value in frequency_map.items():
		print(f"character '{key}' appears: {value} times")
		
frequency_of_char(input_string='programming')
#################################################################
