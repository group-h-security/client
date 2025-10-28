*tue 28 oct 2025* - ryan sheridan

### mTLS explanation and handshake

cert generation, mTLS is an extension of TLS, TLS being the encryption protocol used on HTTPS, mTLS goes one step further and is where both sides validate each other

**handshake**

1. server says heres my cert, i am the server
2. client checks if they trust that cert
3. client sends there cert to server
4. server checks if they trust that cert
5. they both agree

we need to create certs for both the client and the server for mTLS, some terminology would include **CA** which means **Certificate Authority** 

**CA** is the **root** of trust, anyone with a certificate signed by this **CA** is trusted 

in our case we have the server certificate, which proves the identity of the server, which is signed by the CA, and the client certificate, which proves the identity of the client, signed by the CA

**keystore**

this contains YOUR identity, this is the private key + certificate. e.g. YOUR passport

**truststore** 

the certifcates YOU trust, usually the CA certificate. e.g. list of countries whose passports you accept

**what the server and client needs**

```
server-keystore.jks -> servers identity
server-truststore.jks -> list of trusted clients 
---
client-keystore.jks -> client identity
client-truststore.jks -> list of trusted servers
```

**`generate-certs.sh`**

creates the following

```
server-keystore.jks <- servers identity 
server-truststore.jks <- trusted clients 
client-keystore.jks <- client identity 
client-truststore.jks <- trusted servers 

**important**
ca-cert.pem, ca-key.pem <- CA files (root of trust)
```

**the script**

the steps look like

1. creates a CA (certificate authority)
	- our own certificate authority, in production apparently we would use something like lets encrypt
2. creates server certificate (signed by CA)
	- server private key `server-key.pem`
	- servers certificate `server-cert.pem`
	- java format `server-keystore.jks`
3. creates client certificate (signed by CA)
	- client private key `client-key.pem`
	- client certificate `client-cert.pem`
	- java format `client-keystore.jks`
4. creates truststores
	- both contain CA certificate
	- allows server to trust any client signed by this CA 
	- allows client to trust any server signed by this CA 

**testing**

```bash
./gradlew test
```
