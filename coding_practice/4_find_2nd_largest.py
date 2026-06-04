def find_second_largest_sort(nums):
    # 1. Remove duplicates to handle ties for the highest number
    unique_nums = set(nums)
    
    # 2. Safety check: Ensure we have at least two unique numbers
    if len(unique_nums) < 2:
        return None
        
    # 3. Sort ascending and grab the second item from the end
    return sorted(unique_nums)[-2]

# Test cases
print(find_second_largest_sort([10, 20, 4, 45, 99, 99]))  # Output: 45
print(find_second_largest_sort([5, 5, 5]))               # Output: None

###########################3

user_input = input("Enter bids (Example: Alice:100 Bob:200 Charlie:1200):\nInput: ")

# 1. Break the string into a list of separate bids
raw_items = user_input.split(" ")

bid_ledger = {}

# 2. Extract names and numbers simply
for item in raw_items:
    name, amount_text = item.split(":")
    bid_ledger[name] = int(amount_text)

# 3. Find the second highest number using a set and [-2]
unique_amounts = set(bid_ledger.values())
sorted_amounts = sorted(unique_amounts)
second_highest_value = sorted_amounts[-2]

# 4. Find who placed that bid using a simple for loop
runner_up_name = ""
for name in bid_ledger:
    if bid_ledger[name] == second_highest_value:
        runner_up_name = name

# 5. Print results
print(f"The second highest bid is: {second_highest_value} placed by {runner_up_name}")

