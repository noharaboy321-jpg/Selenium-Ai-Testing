# Write raw Python code to open a text configuration file, read its lines, 
# find a row starting with 'BASE_URL', and extract its assigned value.

def extract_key_from_file(target_key: str):
	file_path = "something/12"
	try:
		with open(file_path, 'r') as file:
		
			for line in file:
				clear_line = line.strip()
				
				if not clear_line and clear_line.starts_with('#'):
					continue
				
				if clear_line.starts_with(target_key):
					if "=" in clear_line:
						key, value = clear_line.split("=",1)
						
						return value.strip()
			
			
			
	except FileNotFoundError:
		print('')
	except IOError as e:
		print(f'{e}')
		
	return None
	