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

        