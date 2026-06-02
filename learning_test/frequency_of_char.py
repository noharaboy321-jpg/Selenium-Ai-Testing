"""Write a Python function that takes a string input and prints the frequency of each character without importing any modules (like collections.Counter)."""

def frequency_of_char(input_string: str) -> dict:
	
	frequency_map = {}
	
	for char in input_string:
		if char in frequency_map:
			frequency_map[char] += 1
		else:
			frequency_map[char] = 1
			
	for key, value in frequency_map.items():
		print(f"character '{key}' appears: {value} times")
		

frequency_of_char(input_string='')