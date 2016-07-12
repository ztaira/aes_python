AES in Python
=============

Hack-A-Week 1: An attempt at implementing the AES in python, for funsies.
Don't use this for anything serious.

## Features:
- Based on [NIST whitepaper - FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
- Satisfies all NIST checks for 128-bit key expansion and text encryption
- Additional tests are included in the webpage in the tests.dir

## What it does:
- Encrypts a file using the Advanced Encryption Standard for 128-bit keys
- Outputs step-by-step values of the cipher key during key expansion
- Outputs step-by-step values of the state array during encryption rounds
- Outputs resulting hexadecimal string(s) to a text file

## What it does not do:
- Use CBC, CFB, or any other modes of operation to alter identical blocks
- Encrypt the text in place (this creates a text file called encodedfile.txt)
- Implement the AES for 192 or 256-bit keys

## Reasons for not doing things:
- I reach the end of my self-imposed time limit

### Included files:
```
- aes.py...........Main file to run. Contains aes object template/main function
- rcon.txt.........Contains the hex data for the rcon table used in key expansion
- sbox.txt.........Contains the hex data for the sbox table used in encryption
- tests/...........Stores the nist whitepaper and site where I got test vectors
- README.md........This readme file.
- appendixb.txt....Text to test. From appendix B of NIST whitepaper. 
- appendixc.txt....Text to test. From appendix C of NIST whitepaper. 
- encodedfile.txt..Output containing the results of encrypting appendixc.txt 
```

:D

Zach

