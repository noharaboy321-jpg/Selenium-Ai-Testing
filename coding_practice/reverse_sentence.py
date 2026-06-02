def reverse_words_easy(sentence):
    current_word = ""
    result = ""
    
    for char in sentence:
        if char != " ":
            current_word += char
        else:
            if current_word != "":
                if result != "":
                    result = current_word + " " + result
                else:
                    result = current_word
                current_word = ""
    if current_word != "":
        if result != "":
            result = current_word + " " + result
        else:
            result = current_word  
            
    return result
            
print(reverse_words_easy("Python is fun")) 
# Output: "fun is Python"
##############################################################
def reverse_string_loop(text):
    reversed_text = ""
    
    for char in text:
        # Glues the new character to the FRONT of our accumulated text
        reversed_text = char + reversed_text
        
    return reversed_text

print(reverse_string_loop("hello"))  # Output: "olleh"
#########################################3
def reverse_sentence(sentence):
    words = sentence.split()  # Split the sentence into words
    result = ""
    for word in words:
        result = word + " " + result  # Prepend each word to the result
    
    return result.strip()  # Remove any trailing space
print(reverse_sentence("Python is fun")) 
# Output: "fun is Python"
##########################################
def is_full_palindrome(text):
    # Lowercase everything and keep only alphanumeric characters (letters and numbers)
    clean_text = "".join([char.lower() for char in text if char.isalnum()])
    
    return clean_text == clean_text[::-1]

print(is_full_palindrome("A man, a plan, a canal: Panama"))  # Output: True
