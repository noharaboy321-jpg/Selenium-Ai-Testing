def reverse_string_loop(text):
    reversed_text = ""
    
    for char in text:
        # Glues the new character to the FRONT of our accumulated text
        reversed_text = char + reversed_text
        
    return reversed_text

print(reverse_string_loop("hello"))  # Output: "olleh"


##############################################

def reverse_string_easy(text):
    # The [::-1] syntax tells Python to read the string from back to front
    return text[::-1]

# Test cases
print(reverse_string_easy("hello"))      # Output: "olleh"
print(reverse_string_easy("python"))     # Output: "nohtyp"
print(reverse_string_easy("12345"))      # Output: "54321"
