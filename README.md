# OWN - File Encryption
## Description
Uses RSA Algorithm to encrypt files. No private key is needed tho, only a password. The password is transformed to a bigger (prime) number, this is then used as the decriptor (d).

## Usage
```
java -jar paRSA.jar
```
- ```-i``` or ```--init``` to create a keyfile with given name
- ```-k``` or ```--keyfile``` name of the keyfile, contains ```(n,e,diff)```
- ```-e``` or ```--encrypt``` to encrypt a file with given name
- ```-d``` or ```--decript``` to decript a file with given name
- ```-v``` or ```--verbose``` to print the decripted file
- ```-s``` or ```--save``` to save the decripted file

## Threat Modelling
- no obvious weakness, see [here](Threat_Modelling.md)

## TODO
- this project, but one with Elliptic Curves and one with Diffie Hellman instead RSA
- implement threads for encripting and decripting
- create sign and verify logic

## Implementation Comments
- read and write bytes to files, not as strings
