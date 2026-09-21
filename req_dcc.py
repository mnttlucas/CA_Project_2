from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import hashlib
import json
import os

DCC_OWNER_PRIVATE_KEY = "OWNER/private_key.pem"
DCC_OWNER_PUBLIC_KEY = "OWNER/public_key.pem"

def generate_keys():
	# Keys already exists, we load them
	if os.path.exists(DCC_OWNER_PRIVATE_KEY) and os.path.exists(DCC_OWNER_PUBLIC_KEY):
		with open(DCC_OWNER_PRIVATE_KEY, "rb") as f:
			private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
		with open(DCC_OWNER_PUBLIC_KEY, "rb") as f:
			public_key = serialization.load_pem_public_key(f.read())
	# If any of them doesn't exist, we (re)generate them
	else:
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
		public_key = private_key.public_key()
		with open(DCC_OWNER_PRIVATE_KEY, "wb") as f:
			f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
		with open(DCC_OWNER_PUBLIC_KEY, "wb") as f:
			f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
	return private_key, public_key

def derive_mask(password, attribute_name):
	return hashlib.sha256(f"{password}:{attribute_name}".encode()).digest()

def request_dcc():
	private_key, public_key = generate_keys()
	public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
	# Get attributes from user, he decides what he wants to enter
	# Attributes could also be statically implemented and asked for values
	print("Enter your identity attributes:")
	attributes = {}
	while True:
		name = input("Attribute name (or 'exit' to finish): ")
		if name.lower() == "exit":
			break
		value = input(f"Value for {name}: ")
		attributes[name] = value
	# Get user password
	password = input("Enter a password for the DCC: ")
	request_data = {"attributes": [], "digest_function": "SHA-256", "public_key": public_key_pem}
	for name, value in attributes.items():
		mask = derive_mask(password, name)
		request_data["attributes"].append({"name": name, "value": value, "mask": mask.hex()})
	output_file = "dcc_request.json"
	with open(output_file, "w") as f:
		json.dump(request_data, f, indent=4)
	print(f"[+] DCC request saved to {output_file}.")

if __name__ == "__main__":
	request_dcc()