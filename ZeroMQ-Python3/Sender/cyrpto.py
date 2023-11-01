# def encyrpt_file(file_name: str) -> None:
# 	global file_data_bytes
# 	try:
# 		with open(file_name, "rb") as f:
# 			file_data_bytes = f.read()
# 	except FileNotFoundError as e:
# 		sys.exit(f"usage: {sys.argv[0]} [-h] [-p P] -n N\n{sys.argv[0]}: error: argument -N: {file_name} does not exist.")
# 	# TODO: Encyrpt File Data
# 	return None


def encyrpt(data: bytes, key: bytes) -> bytes:
	# TODO impliment
	return data

def decyrpt(data: bytes, key: bytes) -> bytes:
	# TODO impliment
	return data