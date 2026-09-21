from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib
import json
import os
import sys

DCC_ISSUER_PUBLIC_KEY = "ISSUER/public_key.pem"

def derive_mask(password, attribute_name):
	return hashlib.sha256(f"{password}:{attribute_name}".encode()).digest()

def verify_signature(public_key, data, signature):
	try:
		public_key.verify(bytes.fromhex(signature), json.dumps(data, sort_keys=True).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
		return True
	except Exception as e:
		print(f"[!] Signature verification failed: {e}.")
		return False

def check_min_dcc(min_dcc_file):
	# Load the minDCC file
	if not os.path.exists(min_dcc_file):
		print(f"[!] minDCC file '{min_dcc_file}' not found.")
		return
	with open(min_dcc_file, "r") as f:
		min_dcc = json.load(f)
	producer_public_key = serialization.load_pem_public_key(min_dcc["public_key"].encode(), backend=default_backend())
	# Check producer signature
	fields_to_verify = {"original_commitments": min_dcc["original_commitments"], "digest_function": min_dcc["digest_function"], "disclosed_attributes": min_dcc["disclosed_attributes"], "public_key": min_dcc["public_key"], "issuer_signature": min_dcc["issuer_signature"]}
	producer_signature_value = min_dcc["producer_signature"]["value"]
	if not verify_signature(producer_public_key, fields_to_verify, producer_signature_value):
		print("[!] Invalid producer signature.")
		return False
	print("[+] Valid producer signature.")
	# Check DCC issuer signature
	with open(DCC_ISSUER_PUBLIC_KEY, "rb") as f:
		issuer_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
	commitment_values = {}
	for attr in min_dcc["original_commitments"]:
		key, value = next(iter(attr.items()))
		commitment_values[key] = value
	fields_to_verify = {"commitment_values": commitment_values, "public_key": min_dcc["public_key"]}
	issuer_signature_value = min_dcc["issuer_signature"]["value"]
	if not verify_signature(issuer_public_key, fields_to_verify, issuer_signature_value):
		print("[!] Invalid issuer signature.")
		return False
	print("[+] Issuer signature is valid.")
	# Calculate commitments and check with the original commitments
	for attr in min_dcc["disclosed_attributes"]:
		name = attr["name"]
		value, mask_hex = attr["value_and_mask"]
		mask = bytes.fromhex(mask_hex)
		computed_commitment = hashlib.sha256(f"{name}:{value}".encode() + mask).hexdigest()
		if not any(computed_commitment in item.values() for item in min_dcc["original_commitments"]):
			print(f"[!] Commitment error for attribute '{name}'.")
			return False
	print("[+] All commitments are valid.")
	print("[+] minDCC validation successful.")
	return True

def main():
	if len(sys.argv) != 2:
		print("[!] Usage:", sys.argv[0], "[minDCC File].")
		return
	check_min_dcc(sys.argv[1])

if __name__ == "__main__":
	main()