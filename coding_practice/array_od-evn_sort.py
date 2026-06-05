"""Array Sorting: "Given an array int arr[] = {2,5,8,7,1,3,6,4,5,9}, 
write an optimized algorithm to shift all even numbers to the left and 
all odd numbers to the right."
"""

def shift_even_left(arr: list[int]) -> list[int]:
    left  = 0              # 👈 Start of array
    right = len(arr) - 1   # 👈 End of array

    while left < right:    # 👈 Run until pointers meet

        while left < right and arr[left] % 2 == 0:
            left += 1      # 👈 Skip evens on the left (they're correct)

        while left < right and arr[right] % 2 != 0:
            right -= 1     # 👈 Skip odds on the right (they're correct)

        if left < right:
            arr[left], arr[right] = arr[right], arr[left]  # 👈 Fix mismatch
            left  += 1     # 👈 Move inward after swap
            right -= 1     # 👈 Move inward after swap

    return arr             # 👈 In-place modified array


def rearrange(arr: list[int]) -> list[int]:

	left_counter, right_counter = 0, len(arr) - 1
	
	while left_counter < right_counter:
	
		if arr[left_counter] % 2 == 0:
			left_counter +=1
		
		elif arr[right_counter] % 2 != 0:
			right_counter -=1
		
		else:
			arr[left_counter], arr[right_counter] = arr[right_counter], arr[left_counter]
			left_counter +=1
			right_counter -=1
			
	return arr
		

user_input = input('enter numbers separated by comma: ')
arr = [int(num) for num in user_input.split()]

result = rearrange(arr)
print('rearrange arr is : ', result)
