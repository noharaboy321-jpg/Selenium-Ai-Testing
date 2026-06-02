def compress_string(s: str) -> str:
    # Edge Case: If the string is empty or has only 1 character
    if len(s) <= 1:
        return s
        
    compressed = []
    count = 1
    
    # Loop through the string up to the second-to-last character
    for i in range(len(s) - 1):
        if s[i] == s[i + 1]:
            count += 1
        else:
            # Character changed! Append the letter and its frequency
            compressed.append(s[i])
            compressed.append(str(count))
            count = 1  # Reset count for the next character
            
    # CRITICAL STEP: Don't forget to append the very last character group
    compressed.append(s[-1])
    compressed.append(str(count))
    
    # Convert the list back into a single string
    result = "".join(compressed)
    
    # Return the original string if the compressed version isn't shorter
    return result if len(result) < len(s) else s

# Test cases
print(compress_string("aabcccccaaa"))  # Output: "a2b1c5a3"
print(compress_string("abcd"))         # Output: "abcd" (avoids "a1b1c1d1")
print(compress_string(""))             # Output: "" (empty string edge case)
print(compress_string("a"))            # Output: "a" (single character edge case)