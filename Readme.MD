# Usage
## Generate key pair in local folder
java -jar dstu-cli.jar -g
## Sign file
java -jar dstu-cli.jar -f t.txt -s -pri priv.dat
## Verify signature on the file
java -jar dstu-cli.jar -f t.txt -v signature.dat -pub pub.dat