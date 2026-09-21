from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import hashlib
import json
import os
import sys
import time

DCC_OWNER_PRIVATE_KEY = "OWNER/private_key.pem"
DCC_OWNER_PUBLIC_KEY = "OWNER/public_key.pem"

def derive_mask(password, attribute_name):
	return hashlib.sha256(f"{password}:{attribute_name}".encode()).digest()

def sign_min_dcc(fields_to_sign, private_key):
	serialized_data = json.dumps(fields_to_sign, sort_keys=True).encode()
	signature = private_key.sign(serialized_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	return signature.hex()

def generate_min_dcc(dcc_file, min_dcc_file):
	# Load the DCC file
	if not os.path.exists(dcc_file):
		print(f"[!] DCC file '{dcc_file}' not found.")
		return
	with open(dcc_file, "r") as f:
		dcc = json.load(f)
	# Ask the user for the disclosed attributes
	print("Enter the attributes you want to disclose (separe them by ,):")
	disclosed_attributes = input().split(",")
	disclosed_attributes = [attr.strip() for attr in disclosed_attributes]
	# Ensures that the attributes exist in the DCC
	existing_attributes = {attr["name"]: attr for attr in dcc["attributes"]}
	for attr in disclosed_attributes:
		if attr not in existing_attributes:
			print(f"[!] Attribute '{attr}' not found in the DCC.")
			return
	# Load the owner's private key
	with open(DCC_OWNER_PRIVATE_KEY, "rb") as f:
		private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
	# Get user password
	password = input("Enter your password: ")
	min_dcc = {"original_commitments": [{attr["name"]: attr["commitment"]} for attr in dcc["attributes"]], "digest_function": dcc["digest_function"], "disclosed_attributes": [], "public_key": dcc["public_key"], "issuer_signature": dcc["issuer_signature"]}
	for attr_name in disclosed_attributes:
		attr_value = existing_attributes[attr_name]["value"]
		mask = derive_mask(password, attr_name)
		min_dcc["disclosed_attributes"].append({"name": attr_name, "value_and_mask": (attr_value, mask.hex()),})
	# Add the producer signature
	fields_to_sign = { "original_commitments": min_dcc["original_commitments"], "digest_function": min_dcc["digest_function"], "disclosed_attributes": min_dcc["disclosed_attributes"], "public_key": min_dcc["public_key"], "issuer_signature": min_dcc["issuer_signature"]}
	min_dcc_producer_signature = sign_min_dcc(fields_to_sign, private_key)
	min_dcc["producer_signature"] = {"value": min_dcc_producer_signature, "timestamp": time.time(), "algorithm": "RSA-PSS-SHA256"}
	with open(min_dcc_file, "w") as f:
		json.dump(min_dcc, f, indent=4)
	print(f"[+] Minimal DCC saved to {min_dcc_file}.")

def main():
	if len(sys.argv) != 3:
		print("[!] Usage :", sys.argv[0], "[DCC File] [Output minDCC Name].")
		return
	generate_min_dcc(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
	main()