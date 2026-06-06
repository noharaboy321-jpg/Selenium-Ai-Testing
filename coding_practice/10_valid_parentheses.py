"""Problem B: Valid Parentheses 
(Validates API response logs or code block parsing)Scenario: 
Check if string inputs containing brackets (), {}, [] are closed in the correct order."""

def is_valid_string(s: str)-> bool:
    stack =[]
    mapping = {')':'(', '}':'{', ']':'['}
    for char in s:
        if char in mapping:
            top_element = stack.pop() if stack else '#'
        
            if mapping[char] != top_element:
                return False
        else:
            stack.append(char)
        
    return len(stack) == 0
#Input: "({[]})" → Output: True  
print(is_valid_string("({[]})"))  # Output: True
#Input: "({[})" → Output: False 