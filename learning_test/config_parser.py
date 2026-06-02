import configparser


config = configparser.configparser()
config_file_path = os.path.join(os.path.dirname(__file__), 'config.property')
	
if not os.path.exists(config_file_path):
	raise FileNotFoundError(f'Configuration file is missing at : {config_file_path}')
		
		
config.read(config_file_path)


def config_fetcher(section: str, key: str) -> str:
	return config.get(section, key)
	


try:
	
	db_host = config_fetcher('DATABASE','DB_HOST')
	api_timeout = config_fetcher('API','API_TIMEOUT')
	
	print(f'host {db_host} and timeout is {api_timeout}')
	
except configparser.NoSectionError:
		print("...")
except configparser.NoOptionError:
		print("...")
except FileNotFoundError as e:
		print(e)
