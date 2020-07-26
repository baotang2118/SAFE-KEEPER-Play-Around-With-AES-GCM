import os
import gc
import sys
import getpass
import argparse
from time import perf_counter 

from myClass import file_crypto


def help():
	parser = argparse.ArgumentParser(description='''@Safe Keeper - keeps your secret safe and confident, file encryption/decryption comes with CLI version. 
													If the file's smaller than 1.25GB, this program will load whole file to memory, make sure that you have
													enough memory to contain it or it will run to error on decrypting. Remember to close any opening file
													before start this process.
													Author: baotd''')
	parser.add_argument('-e', '--encrypt', type=str, help='type <file>, a file will be encrypted')
	parser.add_argument('-d', '--decrypt', type=str, help='type <file>, a file will be decrypted')
	parser.add_argument('-o', '--object', type=str, help='type <folder>, a directory will contain the output')
	parser.add_argument('-p', '--password', type=str, help='your password')
	parser.add_argument('-a', '--associate_data', type=str, help='''your name, your dog, PC ID, version of OS or your high school gpa etc.,
													whatever you want, if not, it will be replaced by a default value''')
	parser.add_argument('-r', '--remove', action='store_true', help='simple remove the imput')
	parser.add_argument('-w', '--wipe', action='store_true', help='secure delete data, overwrite exist input with 3 phases (0,1,random) before removing it')
	parser.add_argument('-s', '--sha512', action='store_true', help='''print hash of raw data and encrypted data 
								in encryption progress. This option is usually unnecessary because we always carry our data; however, 
								a rare situation, when we compeletely lost 1 chuck, still happens. Hence the big file is sliced into small chucks, 
								each of them is constructed by (nonce|E(data)|tag) and encrypted independently, if we fully lost 1 chuck, 
								decryption process would work normally but the decrypted data is wrong''')
	return parser.parse_args()


def main():
	
	t1_start = perf_counter()
	args = help()
	a = file_crypto()
	if not args.password:
		p = getpass.getpass()
		a.set_passwd(p)
	else:
		a.set_passwd(args.password)

	if args.encrypt and args.decrypt:
		print ("Cannot set encryptor and decryptor at the same time")
		sys.exit()
	if not args.object:
		print ("Output directory must be specific")
		sys.exit()

	if args.encrypt:
		print ("Validating password ... .. .")
		if not a.check_password():
			print ("Invalid password ... .. .")
			sys.exit()
		
		if os.path.isfile(args.encrypt) and os.path.isdir(args.object):				
			print ("Encrypting ... .. .")
			a.set_fi(args.encrypt)
			a.set_fo(os.path.join(args.object, os.path.basename(args.encrypt) + ".enc"))			
			if args.associate_data:
				a.set_aad(args.associate_data)
			a.encrypt_file()
			print ("Encrypt done.")
		else:
			print ("File or folder do not exist")
			sys.exit()
		
		if args.sha512:
			calc_hash = a.calculate_hash()
			print ("Plain data", calc_hash[0])
			print ("Encrypted data", calc_hash[1])

		if args.wipe:
			print ("Wiping data ... .. .")
			a.wipe_data()
			print ("Wiped.")
			args.remove = True
		
		if args.remove:
			print ("Removing data ... .. .")
			a.simple_delete()
			print ("Removed.")

	if args.decrypt:
		print ("Validating password ... .. .")
		if not a.check_password():
			print ("Invalid password ... .. .")
			sys.exit()
		
		if os.path.isfile(args.decrypt) and os.path.isdir(args.object):
			print ("Decrypting ... .. .")
			a.set_fi(args.decrypt)
			a.set_fo(os.path.join(args.object, os.path.basename(args.decrypt)[:-4]))
			if args.associate_data:
				a.set_aad(args.associate_data)
			a.decrypt_file()
			print ("Decrypt done.")
		else:
			print ("File or folder do not exist")
			sys.exit()
		
		if args.sha512:
			calc_hash = a.calculate_hash()
			print ("Encrypted data", calc_hash[0])
			print ("Plain data", calc_hash[1])

		if args.wipe:
			print ("Wiping data ... .. .")
			a.wipe_data()
			print ("Wiped.")
			args.remove = True
		
		if args.remove:
			print ("Removing data ... .. .")
			a.simple_delete()
			print ("Removed.")

	t1_stop = perf_counter() 
	print("Elapsed time during the whole program in seconds:", t1_stop-t1_start) 

	gc.collect()


if __name__ == '__main__':
	main()
