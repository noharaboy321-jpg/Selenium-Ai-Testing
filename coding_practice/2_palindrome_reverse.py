"""Write a Python function to reverse the individual words of a string while keeping their exact sentence positions identical """

def reverse_word(sentence: str) -> str:
	
	result=" ".join([word[::-1] for word in sentence.split(" ")])
	
print(reverse_word('xyz abc pqr'))
##################################################################
def reverse_sentence(sentence):
    words = sentence.split()  # Split the sentence into words
    result = ""
    for word in words:
        result = word + " " + result  # Prepend each word to the result
    
    return result.strip()  # Remove any trailing space
print(reverse_sentence("Python is fun")) 
# Output: "fun is Python"
##########################################################
def valid_palindrome(s):
    k = "".join(j.lower() for j in s if j.isalnum())
    result=""
    for i in k:
        result = i + result
    return s==result
####################################################################
def valid_palindrome(s):
    left = 0
    right = len(s) - 1
    while left < right:
        if not s[left].isalnum():
            left += 1
            continue
        elif not s[right].isalnum():
            right -= 1
            continue
        elif s[left].lower() != s[right].lower():
            return False
        left+=1
        right-=1
    return True
##############################################################
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
##############################################
def reverse_generic_simple(text):
    letters = [char for char in text if char.isalpha()]
    reversed_letters = letters[::-1]
    
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

################################################3
s1 = "acl123digital"

result = []
current_word = ""

for char in s1:
    if char.isalpha():
        current_word += char
    else:
        if current_word:
            result.append(current_word[::-1])
            current_word = ""
        result.append(char)
if current_word:
    result.append(current_word[::-1])
    
print("".join(result))
#########################################################
def is_full_palindrome(text):
    # Lowercase everything and keep only alphanumeric characters (letters and numbers)
    clean_text = "".join([char.lower() for char in text if char.isalnum()])
    
    return clean_text == clean_text[::-1]

print(is_full_palindrome("A man, a plan, a canal: Panama"))  # Output: True