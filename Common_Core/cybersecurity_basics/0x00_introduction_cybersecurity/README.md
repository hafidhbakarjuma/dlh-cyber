0x00 Introduction to Cybersecurity

A collection of Bash scripts covering basic cybersecurity concepts.

Scripts

*0-release.sh Displays the Linux distributor ID

*1-gen_password.sh Generates a random alphanumeric password

*2-sha256_validator.sh Verifies the integrity of a file using SHA256

*3-gen_key.sh Generates a 4096-bit RSA SSH key pair

*4-root_process.sh Lists active processes for a given user

to execute the file first you must use

chmod +x file

bash

./0-release.sh

./1-gen_password.sh 20

./2-sha256_validator.sh test_file <hash>

./3-gen_key.sh new_key

./4-root_process.sh root
