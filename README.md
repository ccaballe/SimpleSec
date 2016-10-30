========================================
SECTION 3 - Application for secure storage of files
========================================

@author: Cristian Caballero Montiel
@NIA: 100081884


Introduction
------------------
This practical work consists on the implementation of a Java application that allows the secure storage of files in
the local hard disk. This application supports encryption and signing of files.


Content of the zip
------------------
In this zip you can find some java files and one jar file. Most important files are:

- RSALibrary.java: Library that contains full implementation of the encryption, decryption, sign and verify using RSA.
- SymmetricCipher.java: Library that contains full implementation of the encryption and decryption using AES-CBC.
- SimpleSec.java: Main to encrypt/decrypt files.
- SimpleSec.jar: Runnable jar.

How to test
-----------
There are two ways to check if the functionality work as expected:

- Compile java files and run SimpleSec in this way:
    1. To generate public and private keys: java SimpleSec g
    2. To encrypt and sign a file: java SimpleSec e [sourceFile] [destFile]
    3. To verify and decrypt a file: java SimpleSec d [sourceFile] [destFile]
- Run SimpleSec.jar with:
	1. To generate public and private keys: java -jar SimpleSec.jar g
    2. To encrypt and sign a file: java -jar SimpleSec.jar e [sourceFile] [destFile]
    3. To verify and decrypt a file: java -jar SimpleSec.jar [sourceFile] [destFile]

