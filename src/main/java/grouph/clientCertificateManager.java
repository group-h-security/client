package grouph;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.io.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.security.cert.CertificateFactory;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class clientCertificateManager {//handle certs and stores

    private static final String certificatesDirectory = "certs";//pointer to certs directory
    private static final String storesDirectory = "stores";//pointer to certs directory
    private static final String pass;

    static {
        try {
            pass = Files.readString(Path.of("stores/keystorePass.txt"), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void start() throws Exception {


        Path certsDir = Paths.get("certs");
        Files.createDirectories(certsDir);
        String csrPEM = generateCsr();
        Path csrPath = certsDir.resolve("client.csr");

        Files.writeString(csrPath, csrPEM);
        System.out.println("CSR Generated at "+new File("/certs/client.csr").getAbsolutePath());

        //declare paths to make life easier
        Path clientPrivateKeyFile = Paths.get(storesDirectory, "client-key.pem");

        Path clientCsrFile = Paths.get(certificatesDirectory, "client.csr");

        Path clientCrtFile = Paths.get(storesDirectory, "client.crt");

        Path intermediateCrtFile = Paths.get(storesDirectory, "intermediate.crt");
        //Path rootCrtFile = Paths.get(certificatesDirectory, root.crt); //needs to be added in

        certificatesRequest(clientCsrFile);//sedn the csr to the flask server to attempt to get client.crt and intermediate.crt

        PrivateKey clientPrivKey = loadKeyFromPkcs8(clientPrivateKeyFile);//call method to load the private key of the client

        //certificate chain will flow back up to the root authority to verify if a certificate during the handshake is valid and trusted
        // -O. So this is loading the client crt into the chain?
        List<X509Certificate> certChain;
        try (InputStream inp = Files.newInputStream(clientCrtFile)) {
            certChain = new ArrayList<>(loadCertificateChain(inp)); // make mutable
        }

        // was "intermediateCsr"
        X509Certificate intermediateCert = loadCertificate(intermediateCrtFile);

        // ensure intermediate is included after the leaf
        boolean hasIntermediate = certChain.stream()
                .anyMatch(c -> c.getSubjectX500Principal().equals(intermediateCert.getSubjectX500Principal()));
        if (!hasIntermediate) {
            certChain.add(intermediateCert);
        }

// was "clienKeyStore"
        KeyStore clientKeyStore = KeyStore.getInstance("JKS");

// load existing keystore if it exists, else create new
        Path ksPath = Paths.get(storesDirectory, "client-keystore.jks");
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                clientKeyStore.load(in, pass.toCharArray());
            }
        } else {
            System.err.println("TRUSTSTORE NOT FOUND?");
        }

// store private key + chain (leaf first, no root)
        clientKeyStore.setKeyEntry(
                "client",
                clientPrivKey,
                pass.toCharArray(),
                certChain.toArray(new X509Certificate[0])
        );

// save back to same path (fixed missing separator)
        try (OutputStream out = Files.newOutputStream(ksPath)) {
            clientKeyStore.store(out, pass.toCharArray());
        }

        // O. We dont need to add the intermediate to the trust store - we send it with the client crt during mTLS
        /*
        KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("rootCrt", intermediateCsr);//need to make sure it matches when added
        try (FileOutputStream out = new FileOutputStream(certificatesDirectory + "/c-TrustStore.jks")) {
            clientTrustStore.store(out, pass.toCharArray());
        }
        System.out.println("Clients keystore and truststore made without issue!");

         */
        }



            private void certificatesRequest(Path clientCsrFile) throws Exception {
                String seperator = "----Boundary" + System.currentTimeMillis();
                URI flaskServURI = new URI("http://127.0.0.1:5000/sign");
                HttpURLConnection flaskServConn = (HttpURLConnection) flaskServURI.toURL().openConnection();

                flaskServConn.setDoOutput(true);//set outp
                flaskServConn.setRequestMethod("POST");//post gonna be used for sending a certificate signing request using a key generated in openssl
                flaskServConn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + seperator);//letting the ca flask server know were sending a multu part request 

                try (OutputStream o = flaskServConn.getOutputStream();
                    PrintWriter w = new PrintWriter(new OutputStreamWriter(o, StandardCharsets.UTF_8), true)) {

                    w.append("--").append(seperator).append("\r\n");
                    w.append("Content-Disposition: form-data; name=\"csr\"; filename=\"client.csr\"\r\n");
                    w.append("Content-Type: application/octet-stream\r\n\r\n");
                    w.flush();

                    Files.copy(clientCsrFile, o);
                    o.flush();

                    w.append("\r\n--").append(seperator).append("--\r\n");
                    w.flush();
                }

                int statusCode = flaskServConn.getResponseCode();
                if (statusCode != 200) {
                    String errorMsg = "";
                    try (InputStream errorStream = flaskServConn.getErrorStream()) {
                        if (errorStream != null)
                            errorMsg = new String(errorStream.readAllBytes(), StandardCharsets.UTF_8);
                    }
                    throw new IOException("Failed to receive certificate. HTTP " + statusCode + ": " + errorMsg);
                }

            try (InputStream inpstream = flaskServConn.getInputStream()) {
            String pemPK = new String(inpstream.readAllBytes(), StandardCharsets.UTF_8);
            int splitIndex = pemPK.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length();
            String clientPem = pemPK.substring(0, splitIndex);
            String intermediatePem = pemPK.substring(splitIndex).trim();

            Files.writeString(Paths.get(storesDirectory, "client.crt"), clientPem, StandardCharsets.UTF_8);
            Files.writeString(Paths.get(storesDirectory, "intermediate.crt"), intermediatePem, StandardCharsets.UTF_8);
        }

    }

    private PrivateKey loadKeyFromPkcs8(Path keyPath) throws Exception {
        String pemPK = Files.readString(keyPath, StandardCharsets.US_ASCII).trim();
        String base64 = pemPK.replace ("-----BEGIN PRIVATE KEY-----", "") .replace("-----END PRIVATE KEY-----", "") .replaceAll("\\s", "");
        byte[] pkBytes = Base64.getDecoder().decode(base64);//decode private key bytes form pkcs8.key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private List<X509Certificate> loadCertificateChain(InputStream inp) throws Exception {
        String pemPK = new String(inp.readAllBytes(), StandardCharsets.UTF_8);
        Pattern pemSections = Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");
        Matcher pemPKMatcher = pemSections.matcher(pemPK);//regex applied to file grabbing key byts
        CertificateFactory certfac = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        while (pemPKMatcher.find()) {
            String block = pemPKMatcher.group();
            try (InputStream bis = new ByteArrayInputStream(block.getBytes(StandardCharsets.UTF_8))) {
                certs.add((X509Certificate) certfac.generateCertificate(bis));
            }
        }
        return certs;
    }

    private X509Certificate loadCertificate(Path certPath) throws Exception {
        try (InputStream inp = Files.newInputStream(certPath)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inp);
        }
    }

    public static String generateCsr() throws Exception {
        // Dealing with all the files and dirs
        System.out.println("PWD = " + System.getProperty("user.dir"));
        Path passPath = Path.of("stores/keystorePass.txt");
        Path jksPath  = Path.of("stores/client-keystore.jks");
        if (!Files.exists(passPath)) throw new FileNotFoundException(passPath + " not found");
        if (!Files.exists(jksPath))  throw new FileNotFoundException(jksPath  + " not found");

        // Get the current keystore with the dummy cert
        char[] pass = Files.readString(passPath).trim().toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(jksPath)) {
            ks.load(in, pass);
        }

        //Get the private from that keystore entry
        String alias = "client";
        Key key = ks.getKey(alias, pass);
        if (key == null) throw new KeyStoreException("No private key for alias '" + alias + "'");
        PrivateKey priv = (PrivateKey) key;

        //Get the public key from the dummy cert
        X509Certificate dummy = (X509Certificate) ks.getCertificate(alias);
        if (dummy == null) throw new KeyStoreException("No certificate for alias '" + alias + "'");
        PublicKey pub = dummy.getPublicKey();

        // Start building the CSR, starting with the SAN
        String fqdn = InetAddress.getLocalHost().getCanonicalHostName();
        String host = InetAddress.getLocalHost().getHostName();

        java.util.LinkedHashSet<GeneralName> sans = new java.util.LinkedHashSet<>();
        sans.add(new GeneralName(GeneralName.dNSName, host));
        sans.add(new GeneralName(GeneralName.dNSName, fqdn));
        sans.add(new GeneralName(GeneralName.dNSName, "localhost"));
        sans.add(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));

        // Get all the IP addresses on the machines NICs IPv4 only
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface nif = ifs.nextElement();
                Enumeration<InetAddress> addrs = nif.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    String ip = addrs.nextElement().getHostAddress();
                    if (ip.contains(".")) sans.add(new GeneralName(GeneralName.iPAddress, ip));
                }
            }
        } catch (SocketException se) {
            System.err.println("WARN: Could not enumerate interfaces: " + se.getMessage());
        }

        //Building the subject
        X500Name subject = new X500Name("C=IE,O=Group-H Security,CN=" + fqdn);
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, pub);//Initiate the CSR, with the subject and public key

        // Setting the CSR extensions ie. permissions
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(sans.toArray(new GeneralName[0])));
        extGen.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        extGen.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        // Signing the CSR using SHA256 to confirm the csr isnt edited after creation. That hash is signed with the private key.
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(priv);
        PKCS10CertificationRequest csr = builder.build(signer);

        // Write the CSR out as PEM and return it
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) { w.writeObject(csr); }
        return sw.toString();
    }

    public static void main(String[] args) throws Exception {
        clientCertificateManager c = new clientCertificateManager();
        c.start();
    }
}
