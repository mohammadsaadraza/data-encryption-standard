# data-encryption-standard
An implementation of DES Algorithm using 56-bit key

sample use case of the algorithm

```python
from DES import desBitBlocks, getSubKeys, desEncryption, desDecryption, printText

key='sampleKey'
roundKeys = getSubKeys(key)

plaintext = 'This is a sample PlainText.'
plaintext_blocks = desBitBlocks(plaintext)

#Printing
print("KEY:\n{}\n\nPLAINTEXT: \n{}\n\n".format(key, plaintext))

# Encrypting 64-bit blocks at a time, using desEncryption()
ciphertext_blocks = []
for block in plaintext_blocks:
	ciphertext_blocks.append(desEncryption(block, roundKeys))

# Custom print() to display text from list of 64-bit blocks
printText(ciphertext_blocks, text='CipherText')

# Decrypting 64-bit blocks at a time, using desDecryption()
decrypted_blocks = []
for block in ciphertext_blocks:
	decrypted_blocks.append(desDecryption(block, roundKeys))

# Custom print() to display text from list of 64-bit blocks
printText(decrypted_blocks, text='Decrypted PlainText')
```
Output:
```
KEY:
sampleKey

PLAINTEXT:
This is a sample PlainText.



---------CipherText----------
ócêí↕♥÷²ú¦ÐNE¨>5ÃÎXÕ▬ð(→
---------------------


---------Decrypted PlainText----------
This is a sample PlainText.
---------------------
```
