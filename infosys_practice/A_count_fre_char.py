def count_frequency_manual(text):
    freq_map = {}
    
    for char in text:
        if char in freq_map:
            freq_map[char] += 1  # Increment if we have seen it before
        else:
            freq_map[char] = 1   # Start at 1 for a new character
            
    return freq_map

# Test the function
print(count_frequency_manual("programming"))
