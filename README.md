# OWN - File Encryption
## Description
Uses RSA Algorithm to encrypt files. No private key is needed tho, only a password. The password is transformed to a bigger (prime) number, this is then used as the decriptor (d).

## Usage
via jar file
```
java -jar paRSA.jar
```
or via java class
```
cd out/production/paRSA
java ch.zhaw.cailllev.Main -h
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
- this project, but with Elliptic Curves instead RSA
- add loading bar for prime gen instead of seconds

## Implementation Comments
- read and write bytes to files, not as strings
