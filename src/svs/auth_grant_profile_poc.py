#pip3 install PyJWT
#pip3 install cryptography
# import jwt
import hashlib
import os
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM




class AuthGrantProfilePoc():

	def __init__(self):
		self.algorithm = 'HS256'
		self.secret = 'inacademiaSecret'

	# def re_encode_data(self, token, secret, data):
	# 	hashed_data = {}

	# 	for k,v in data.items():
	# 		hashed_data[k] = self.encrypt(secret, v)

	# 	decoded, headers = self.decode(secret, token)
	# 	hashed_data.update(decoded)
	# 	return self.encode(secret, headers, hashed_data)

	# def decode_payload(self, token, secret):
	# 	unhashed_data = {}
	# 	decoded, headers = self.decode(secret, token)
	# 	for k,v in decoded.items():
	# 		unhashed_data[k] = self.decrypt(secret, v)

	# 	return unhashed_data

	#
	# def encodeJwtToken(self, headers, payload):
	# 	encoded = jwt.encode(payload, self.secret, headers=headers, algorithm=self.algorithm)
	# 	return encoded
	#
	# def decodeJwtToken(self, token):
	# 	decoded = jwt.decode(token, self.secret, algorithms=[self.algorithm])
	# 	headers = jwt.get_unverified_header(token)
	# 	return decoded, headers

	def deriveEncryptionKey(self, passphrase: str, salt: bytes=None) -> [str, bytes]:
	    if salt is None:
	        salt = os.urandom(8)
	    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000), salt


	def encryptData(self, plaintext: str) -> str:
	    key, salt = self.deriveEncryptionKey(self.secret)
	    aes = AESGCM(key)
	    iv = os.urandom(12)
	    plaintext = plaintext.encode("utf8")
	    ciphertext = aes.encrypt(iv, plaintext, None)
	    return "%s-%s-%s" % (hexlify(salt).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(ciphertext).decode("utf8"))


	def decryptData(self, ciphertext: str) -> str:
	    salt, iv, ciphertext = map(unhexlify, ciphertext.split("-"))
	    key, _ = self.deriveEncryptionKey(self.secret, salt)
	    aes = AESGCM(key)
	    plaintext = aes.decrypt(iv, ciphertext, None)
	    return plaintext.decode("utf8")





data = {'old':'old data'}
headers = {"header1": "header1Value", "header2": "header2Value"}

print('1. databbbb : ', data, ' headers : ', headers)

auuth_grant_plugin = AuthGrantProfilePoc()
# token = auuth_grant_plugin.encodeJwtToken(headers, data)
# print ('2. encoded jwt token..', token)
# data, headers = auuth_grant_plugin.decodeJwtToken(token)
# print('3. decoded..', data, headers)
data['new'] = auuth_grant_plugin.encryptData('new data')
print('4. data : ', data, ' headers : ', headers)
# token = auuth_grant_plugin.encodeJwtToken(headers, data)
# print('5. token : ', token)
# decoded_token = auuth_grant_plugin.decodeJwtToken(token)
# print('5.5 decoded token: ', decoded_token)
# data, headers = decoded_token
new_data = auuth_grant_plugin.decryptData(data['new'])
print('6. unhashed data: ', new_data)