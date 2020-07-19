import os
import re
from binascii import hexlify
from struct import pack, unpack
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class file_crypto(object):
	# Class Variable
	__fi = None
	__fo = None
	__passwd = None
	__key = None
	__salt = None
	__aad = b"authenticated data by Safe Keeper"


	def __init__(self):
		super(file_crypto, self).__init__()


	def set_fi(self, fi):
		self.__fi = fi


	def set_fo(self, fo):
		self.__fo = fo


	def set_passwd(self, passwd):
		self.__passwd = passwd


	def set_aad(self, aad):
		self.__aad = bytes(aad,'utf-8')


	def check_password(self):
		if len(self.__passwd) >= 8:
			if re.search(r"[a-zA-Z]", self.__passwd):
				if re.search(r"[0-9]", self.__passwd):
					if re.search(r"[\W]", self.__passwd):
						return True
		return False


	def __pw2key(self, rd_salt):
		if rd_salt:
			self.__salt = os.urandom(16)
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA512(),
			length=32,
			salt=self.__salt,
			iterations=120000,
			backend=default_backend()
		)
		self.__key = kdf.derive(bytes(self.__passwd, 'utf-8'))


	def encrypt_file(self):
		def GCM_easy_mode(fi, fo, aad, key, salt):
			nonce = os.urandom(16)

			with open(fi, "rb") as file:
				with open(fo, "wb") as file1:
					file1.write(pack('>B', 1)) # 1 byte
					file1.write(salt) # 16 bytes
					file1.write(nonce) # 16 bytes
					data = file.read()
					aesgcm = AESGCM(key)
					ct = aesgcm.encrypt(nonce, data, aad)
					file1.write(ct)


		def GCM_hard_mode(fi, fo, aad, key, salt):
			with open(fi, "rb") as file:
				with open(fo, "wb") as file1:
					with open(fo[:-4]+".tag", "wb") as file2:
						file1.write(pack('>B', 2)) # 1 byte
						file1.write(salt) # 16 bytes

						while True:				
							chunk = file.read(16*1024*1024*10)
							if not chunk:
								break

							iv = os.urandom(16)
							file1.write(iv)

							encryptor = Cipher(
								algorithms.AES(key),
								modes.GCM(iv),
								backend=default_backend()
							).encryptor()

							encryptor.authenticate_additional_data(aad)

							ct = encryptor.update(chunk) + encryptor.finalize()
							file1.write(ct)

							file2.write(encryptor.tag)


		def choose_method(fi):
			if os.path.getsize(fi) < 1250000000: # below 1.25GB, GCM easy mode
				return True
			else: # upper 1.25GB, GCM hard mode
				return False


		self.__pw2key(True)
		if choose_method(self.__fi):
			GCM_easy_mode(self.__fi, self.__fo, self.__aad, self.__key, self.__salt)
		else:
			tag = GCM_hard_mode(self.__fi, self.__fo, self.__aad, self.__key, self.__salt)


	def decrypt_file(self):

		def GCM_easy_mode(fi, fo, aad, passwd):
			
			with open(fi, "rb") as file:
				with open(fo, "wb") as file1:
					file.seek(1, 0)
					self.__salt = file.read(16) # 16 bytes
					self.__pw2key(False)
					nonce = file.read(16) # 16 bytes
					data = file.read()	
					aesgcm = AESGCM(self.__key)
					pt = aesgcm.decrypt(nonce, data, aad)
					file1.write(pt)

		def GCM_hard_mode(fi, fo, aad, passwd):
			
			with open(fi, "rb") as file:
				with open(fo, "wb") as file1:
					with open(fi[:-4]+".tag", "rb") as file2:
						file.seek(1, 0)
						self.__salt = file.read(16) # 16 bytes
						self.__pw2key(False)

						while True:
							iv = file.read(16) # 16 bytes
							chunk = file.read(16*1024*1024*10)
							tag = file2.read(16)
							if not chunk:
								break

							decryptor = Cipher(
								algorithms.AES(self.__key),
								modes.GCM(iv, tag),
								backend=default_backend()
							).decryptor()

							decryptor.authenticate_additional_data(aad)

							pt = decryptor.update(chunk) + decryptor.finalize()
							file1.write(pt)

		def choose_method(fi):
			with open(fi, "rb") as file:
				data = file.read(1) # 1 byte
				if not (unpack('>B', data)[0]^1): # GCM easy mode
					return True
				else:
					if not (unpack('B',data)[0]^2): # GCM hard mode
						return False

		if choose_method(self.__fi):
			GCM_easy_mode(self.__fi, self.__fo,self.__aad, self.__passwd)
		else:
			GCM_hard_mode(self.__fi, self.__fo, self.__aad, self.__passwd)


	def wipe_data(self):
		with open(self.__fi, "ab") as delfile:
			length = delfile.tell()
		if length < 104857600: # < 100MB
			with open(self.__fi, "rb+") as delfile:
				delfile.write(b"\x00"*length)
				delfile.seek(0, 0)
				delfile.write(b"\xff"*length)
				delfile.seek(0, 0)
				delfile.write(os.urandom(length))
		else:
			with open(self.__fi, "rb+") as delfile:
				count = length//104857600
				remain = length%104857600
				for i in range(0, count):
					delfile.write(b"\x00"*104857600)
				delfile.seek(0, 0)
				for i in range(0, count):
					delfile.write(b"\xff"*104857600)
				delfile.seek(0, 0)
				for i in range(0,count):
					delfile.write(os.urandom(104857600))
				delfile.write(b"\x00"*remain)
				delfile.seek(-remain, 2)
				delfile.write(b"\xff"*remain)
				delfile.seek(-remain, 2)
				delfile.write(os.urandom(remain))


	def simple_delete(self):
		os.remove(self.__fi)
		if os.path.isfile(self.__fi[:-4]+".tag"):
			os.remove(self.__fi[:-4]+".tag")
		

	def calculate_hash(self):
		digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
		with open(self.__fi, "rb") as file:
			while True:
				chunk = file.read(16*1024*1024*10)
				if not chunk:
					break
				digest.update(chunk)
		hash1 = digest.finalize()
		digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
		with open(self.__fo, "rb") as file:
			while True:
				chunk = file.read(16*1024*1024*10)
				if not chunk:
					break
				digest.update(chunk)
		hash2 = digest.finalize()
		return str(hexlify(hash1)), str(hexlify(hash2))

