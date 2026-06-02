def merged_array(num1, num2):
    result = []
    i = 0
    j = 0
    
    # 1. Main loop: Compare elements side-by-side
    while i < len(num1) and j < len(num2):
        if num1[i] <= num2[j]:
            result.append(num1[i])
            i += 1
        else:
            result.append(num2[j])
            j += 1
            
    # 2. First cleanup loop: Add leftovers from num1
    while i < len(num1):
        result.append(num1[i])
        i += 1
        
    # 3. Second cleanup loop: Add leftovers from num2
    while j < len(num2):
        result.append(num2[j])
        j += 1  # Fixed: Increments j instead of i to avoid infinite loop
    
    return result


if __name__ == "__main__":
    # Input arrays must be sorted before merging
    num1 = [1, 3, 4]
    num2 = [6, 7, 8]
    
    # Call the correct lowercase function name
    merge_list = merged_array(num1, num2)
    
    print("Merged and Sorted Array:")
    print(merge_list)


def merge_into_two_arrays(num1, num2):
    # Initialize pointer 'i' at the end of num1, and 'j' at the start of num2
    i = len(num1) - 1
    j = 0
    
    # 1. Swap elements out of place between the two arrays
    while i >= 0 and j < len(num2):
        if num1[i] > num2[j]:
            # Swap the values
            num1[i], num2[j] = num2[j], num1[i]
            i -= 1
            j += 1
        else:
            # If num1[i] is already smaller than num2[j], 
            # all elements before i are also smaller, so we can stop.
            break
            
    # 2. Sort both arrays individually to fix internal order
    num1.sort()
    num2.sort()


# --- Driver Code to Test ---
if __name__ == "__main__":
    num1 = [1, 4, 7]
    num2 = [2, 3, 8]
    
    print("Before Processing:")
    print(f"num1 = {num1}")
    print(f"num2 = {num2}\n")
    
    merge_into_two_arrays(num1, num2)
    
    print("After Processing:")
    print(f"num1 = {num1}")
    print(f"num2 = {num2}")

    ## num1 = [1, 2, 3]
    ## num2 = [4, 7, 8]

