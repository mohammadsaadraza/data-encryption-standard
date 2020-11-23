from des_config import initial_perm, final_perm, shift_table, PC1, PC2, exp_d, per, sbox
import functools

def asstring(bitArray):
	"""
	Return string representation of bit array
		
		Parameters:
			bitArray (list): an array of bits

		Returns:
			(string): string form of bitArray
	"""
	return ''.join([str(bit) for bit in bitArray])

def printDecorator(func):
	@functools.wraps(func)
	def wrapper(*args, **kwargs):
		print('\n---------{}----------'.format(kwargs['text']))
		val = func(*args, **kwargs)
		print('---------------------\n')
		return val
	return wrapper
	
@printDecorator
def printText(arr,text = ''):
	"""
	Returns text from a list of 64-bit blocks

		Parameters:
			arr (list of 64 length lists): array of 64-bit blocks, to be converted to text
			text (str): Compulsory argument, any text that specifies the text to be printed
		Return:
			None: prints Text 
	"""
	for b in arr:
		print(frombits(b), end='')
	print()

def permutation(block, arr, n):
	"""
	Return a permutated array of the passed bit block array, according to the passed permutation array, up to n bits
	
		Parameters:
			block (list): array to be permutated
			arr: (list): order of permutation
			n (int): the number of bits to be permuted
			
		Return:
			(list): permutated array
	"""
	permut = []
	for i in range(n):
		permut.append(block[arr[i] - 1])
	return permut

# shifting the bits towards left by nth shifts 
def shift_left(k, nth_shifts):
	out = k
	s = []
	for i in range(nth_shifts): 
		for j in range(1,len(k)): 
			s.append(k[j]) 
		s.append(k[0]) 
		out = s 
		s = []  
	return out

# calculating xow of two strings of binary number a and b 
def xor(a, b): 
	ans = [] 
	for i in range(len(a)): 
		if a[i] == b[i]: 
			ans.append(0)
		else: 
			ans.append(1)
	return ans

# Decimal to binary conversion 
def dec2bin(num):  
	res = bin(num).replace("0b", "") 
	if(len(res)%4 != 0): 
		div = len(res) / 4
		div = int(div) 
		counter =(4 * (div + 1)) - len(res)  
		for i in range(0, counter): 
			res = '0' + res 
	return res

# Binary to decimal conversion 
def bin2dec(binary):  
		
	binary1 = binary  
	decimal, i, n = 0, 0, 0
	while(binary != 0):  
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)  
		binary = binary//10
		i += 1
	return decimal

def tobits(s):
	"""
	Returns an array of bits from the passed string
	
		Parameters:
			s (string): any length of string to be converted to bits
			
		Return:
			(list of ints): bits of s
	"""
	result = []
	for c in s:
		bits = bin(ord(c))[2:]
		bits = '00000000'[len(bits):] + bits
		result.extend([int(b) for b in bits])
	return result

def frombits(bits):
	"""
	Returns a string from the passed bit array
	
		Parameters:
			bits (list of ints): any length of list to be converted to string characters
			
		Return:
			(string): string from bits
	"""
	chars = []
	for b in range(len(bits) // 8):
		byte = bits[b*8:(b+1)*8]
		chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
	return ''.join(chars)

def desBitBlocks(string, block_size=64):
	"""
	Returns string in 'block_size' length list of lists, default is 64-bits. To be used for encryption and decryption
	
		Parameters:
			string (str): any length of python string
			block_size (int): resulting bit block size
			
		Return:
			(list of lists): string split up into bits
	"""
	blocks = []
	byteArray = tobits(string)
	N = len(byteArray)
	if N < block_size:
		blocks.append(byteArray + ([0]*(block_size - N)))
	else:
		for b in range(N // block_size):
			blocks.append(byteArray[b*block_size:(b+1)*block_size])
		remainder = N % block_size
		if remainder > 0:
			temp = byteArray[N-remainder:] + ([0]*(block_size-remainder))
			blocks.append(temp)
	return blocks

def desInitialPermutation(block, arr=initial_perm, n=64):
	permut = []
	for i in range(n):
		permut.append(block[arr[i] - 1])
	return permut

def desFinalPermutation(block, arr=final_perm, n=64):
	permut = []
	for i in range(n):
		permut.append(block[arr[i] - 1])
	return permut

def getSubKeys(key, PC1=PC1, PC2=PC2, shift_table=shift_table):
	"""
	Returns 16 48-bit keys, resulting from the 64-bits of user-specified key. Required for DES Algorithm
	
		Parameters:
			key (list of length 64): enc/dec key
			PC1 (list of length 56): key parity list (DES Algo)
			PC2 (list of length 48): key compression list (DES Algo)
			shift_table (list of length 16): shifting counts of the 16 produced keys (DES Algo)
			
		Return:
			(list of list): 16 48-bit keys
	 """
	# Using only the first 64-bits as encryption key
	key = desBitBlocks(key)[0]

	mutatedKey = permutation(key, arr=PC1, n=56)

	left = mutatedKey[0:28]
	right = mutatedKey[28:56]

	roundKeys = []
	for i in range(16):
		left = shift_left(left, shift_table[i])
		right = shift_left(right, shift_table[i])

		combine = left+right

		k = permutation(combine, arr=PC2, n=48)

		roundKeys.append(k)
	
	return roundKeys

def desEncryption(pt, rkb):
	"""
	Return 64-bit ciphertext of the passed 64-bit plaintext. As in DES Algorithm
	
		Parameters: 
			pt (list): 64-bit array, that is to be encrypted
			rkb (list of lists): 16 48-bit round keys
		
		Returns:
			(list): 64-bit ciphertext
	"""
	# Initial Permutation
	pt = desInitialPermutation(pt, initial_perm, 64)
	
	left = pt[0:32] 
	right = pt[32:64] 
	for i in range(0, 16): 
		#  Expansion D-box: Expanding the 32 bits data into 48 bits  
		right_expanded = permutation(right, exp_d, 48) 
		  
		# XOR RoundKey[i] and right_expanded  
		xor_x = asstring(xor(right_expanded, rkb[i]))
  
		# S-boxex: substituting the value from s-box table by calculating row and column  
		sbox_str = "" 
		for j in range(0, 8): 
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5])) 
			col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4])) 
			val = sbox[j][row][col] 
			sbox_str = sbox_str + dec2bin(val) 
			  
		# Straight D-box: After substituting rearranging the bits
		sbox_str = [int(i) for i in sbox_str]  
		sbox_str = permutation(sbox_str, per, 32)
		  
		# XOR left and sbox_str 
		result = xor(left, sbox_str) 
		left = result 
		  
		# Swapper 
		if(i != 15): 
			left, right = right, left  
	  
	# Combination 
	combine = left + right 
	  
	# Final permutaion: final rearranging of bits to get cipher text 
	cipher_text = desFinalPermutation(combine, final_perm, 64) 
	return cipher_text

def desDecryption(cipher_text, rkb):
	"""
	Return 64-bit plaintext of the passed 64-bit ciphertext. As in DES Algorithm
	
		Parameters: 
			pt (list): 64-bit array, that is to be decrypted
			rkb (list of lists): 16 48-bit round keys
		
		Returns:
			(list): 64-bit plaintext
	"""
	# To decrypt I only need to reverse the order of roundKeys
	return desEncryption(cipher_text, rkb[::-1]) 


if __name__ == '__main__':
	
	"""
	Sample Use Case of the above functions that implementation Data Encryption Standard
	"""

	key='KaliLinux'
	keyBits = desBitBlocks(key)[0] # To get only the 64 bits of key
	print('Key "{}" in the first 64-bits is {}\nThis will be used as KEY\n'.format(key, asstring(keyBits)))

	roundKeys = getSubKeys(key)

	plaintext = 'This is a sample plain text. This lab has been very complicated but I enjoyed coding it.'
	print('PlainText : \n',plaintext)

	plaintextBlocks = desBitBlocks(plaintext)
	ciphertextBlocks = []

	# Encrypting 64-bit blocks
	for b in plaintextBlocks:
		ciphertextBlocks.append(desEncryption(b, roundKeys))
	printText(ciphertextBlocks, text='CipherText')

	# Decrypting 64-bit blocks
	decrypted_plaintext = []
	for b in ciphertextBlocks:
		decrypted_plaintext.append(desDecryption(b, roundKeys))

	# Printing
	printText(decrypted_plaintext, text='Decrypted PlainText')


