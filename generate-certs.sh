#!/bin/bash 

#https://redkestrel.co.uk/articles/openssl-commands ,this website was a tremendous help in understandig what was happening

set -e

certsDirectory="certs"
password="pass"

mkdir -p "$certsDirectory"

c_Key="$certsDirectory/client.key"
c_Csr="$certsDirectory/client.csr"

openssl genrsa -out "$c_Key" 2048 #generate key pair
openssl req -new -key "$c_Key" -out "$c_Csr" -subj "/CN=Client/O=MyOrg" #make csr with clients private key
openssl pkcs8 -topk8 -inform PEM -in "$c_Key" -outform PEM -nocrypt -out "$certsDirectory/c-pkcs8.key" #makes life easier, Java can now read the key 

echo "succesfully made folder."
echo "succesfully genereated key."
echo "succesfully made csr with key"
echo "sucessfully made pkcs8.key for java to create truststore and keystore easily."
