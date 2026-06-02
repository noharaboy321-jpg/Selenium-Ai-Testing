def reverse_generic_simple(text):
    # 1. Collect all letters and reverse the whole list using [::-1]
    letters = [char for char in text if char.isalpha()]
    reversed_letters = letters[::-1]
    
    # 2. Rebuild the string: if it's a digit keep it, otherwise pop from our reversed letters
    result = []
    for char in text:
        if char.isdigit():
            result.append(char)
        else:
            result.append(reversed_letters.pop(0))
            
    return "".join(result)

# Test with different patterns to show it is generic
print(reverse_generic_simple("acl123digital"))
print(reverse_generic_simple("hello555world"))
print(reverse_generic_simple("123abc456"))


s1 = "acl123digital"

# 1. Grab only the letters and reverse them using [::-1]
reversed_letters = [char for char in s1 if not char.isdigit()][::-1]

output = []
index = 0

# 2. Check each character: keep numbers, otherwise use the reversed letters
for char in s1:
    if char.isdigit():
        output.append(char)  # Appends numeric value as it is
    else:
        output.append(reversed_letters[index])
        index += 1  # Move to the next reversed letter

# 3. Convert the list back to a string
final_result = "".join(output)
print(final_result)
