def words_to_bytes(word_array: list[int]) -> list[int]:
    byte_array = []
    for word in word_array:
        # Mask and shift bit-blocks sequentially
        byte_array.append((word >> 24) % 256)
        byte_array.append((word >> 16) % 256)
        byte_array.append((word >> 8) % 256)
        byte_array.append(word % 256)
    return byte_array
    
    
print(words_to_bytes([0xDEADBEEF]))
for b in words_to_bytes([0xDEADBEEF]):
    print(hex(b))


def bytes_to_words(byte_array: list[int]) -> list[int]:
    if len(byte_array) % 4 != 0:
        raise ValueError("Invalid Byte Array length for 32-bit conversion.")
        
    word_array = []
    for i in range(0, len(byte_array), 4):
        # Shift segments back into a single 32-bit integer workspace
        word = ((byte_array[i] << 24) | 
                (byte_array[i+1] << 16) | 
                (byte_array[i+2] << 8) | 
                byte_array[i+3])
        word_array.append(word)
    return word_array