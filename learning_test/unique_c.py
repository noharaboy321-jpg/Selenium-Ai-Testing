def unique_1_char(s: str):

    charcount_= defaultdict(int)

    for char in s:
        charcount_[char] += 1

    for index, char in enumerate(s):
        if charcount_[char] == 1:
            return char, index
    
    return False
