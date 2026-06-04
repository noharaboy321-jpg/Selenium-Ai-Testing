def maximum_array(arr):
    current_sum = arr[0]
    max_sum = arr[0]
    
    for i in range(1, len(arr)):
        current_sum = max(arr[i], current_sum + arr[i])
        max_sum = max(max_sum, current_sum)
    return max_sum

def double_loop(arr):
    max_sum = arr[0]
    for start in range(len(arr)):
        current_sum = 0
        for end in range(start, len(arr)):
            current_sum = current_sum + arr[end]
            
            if current_sum > max_sum:
                max_sum = current_sum
                
    return max_sum
numbers = [1, -2, 3, 2,4, -1, 2, 1, -5, 4]
print(maximum_array(numbers)) 
print(double_loop(numbers)) 

        
