PASSWORD="$(openssl rand -base64 24)"
# ensure directory exists

rm -f stores/keystorePass.txt stores/client-keystore.p12 stores/client-keystore.jks certs/dummy-cert.pem stores/client-key.pem
mkdir -p stores certs

# clear any existing password file (truncate to zero bytes)
echo "$PASSWORD" > stores/keystorePass.txt

# Generate Private key for the client
openssl genrsa -out stores/client-key.pem 4096

# temp cert so we can store make the jks with the private key entry
openssl req -x509 -new -key stores/client-key.pem -days 1 \
  -subj "/C=IE/O=Group-H Security/CN=temporary" \
  -out certs/dummy-cert.pem

openssl pkcs12 -export -in certs/dummy-cert.pem -inkey stores/client-key.pem \
  -out stores/client-keystore.p12 -name client -passout pass:"$PASSWORD"

keytool -importkeystore \
  -srckeystore stores/client-keystore.p12 -srcstoretype PKCS12 \
  -srcstorepass "$PASSWORD" \
  -destkeystore stores/client-keystore.jks -storepass "$PASSWORD" \
  -deststorepass "$PASSWORD" -noprompt
echo "✓ Client keystore created (client-keystore.jks)"

rm -f stores/client-keystore.p12

## Only need to run once - can persist on github,
keytool -import -file stores/rootCert.crt -alias CARoot -keystore stores/client-truststore.jks \
 -storepass changeit -noprompt
echo "✓ Client truststore created (client-truststore.jks)"
