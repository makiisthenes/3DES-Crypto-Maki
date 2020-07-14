# 3DES-Crypto-Maki
Implementation of 3DES in Python  
DES was the Encryption Standard from 1970s to 1999, but due to small key size, it was deemed unsecure.  
AES is the new standard currently. However DES is still used but in a triple implementation, 3DES which increases the key by 3 times.  
3DES is used in some ePassports and other Hardware Constraint CryptoSystems.  
I created a python implementation of 3DES which is valid 3DES cipher.  
It only currently encrypts, but any 3DES decrypter given the key and cipher text can decrypt messages.  
Can be used for cryptographic projects, but at own risk.  
Python secrets module for used to create cryptographically strong random numbers/ bits for use as initial key.
Key Size are 64bits * 3, and block size of 64bits of plain text can be encrypted at a time.  
Inspiration from Lectures from Christof Paar,  
Michael Peres
