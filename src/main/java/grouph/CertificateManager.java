package grouph;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
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

public class CertificateManager { // handle certs and stores

    private static final String certificatesDirectory = "certs"; // pointer to certs directory in project root
    private static final String pass;

    static {
        try {
            pass = Files.readString(Path.of(DataManager.getDataPath("certs/keystorePass.txt")), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void start() throws Exception {
        // certs should exist in data path
        Path certsDir = Paths.get(DataManager.getDataPath("certs"));
        Files.createDirectories(certsDir);

        String csrPEM = generateCsr();
        Path csrPath = Paths.get(DataManager.getDataPath("client.csr"));

        Files.writeString(csrPath, csrPEM);
        System.out.println("CSR Generated at " + csrPath.toAbsolutePath());

        // declare paths using DataManager.getDataPath for all files except rootCert
        Path clientPrivateKeyFile = Paths.get(DataManager.getDataPath("certs/client-key.pem"));
        Path clientCsrFile = Paths.get(DataManager.getDataPath("client.csr"));
        Path clientCrtFile = Paths.get(DataManager.getDataPath("client.crt"));
        Path intermediateCrtFile = Paths.get(DataManager.getDataPath("intermediate.crt"));

        importCATruststore();

        // Attempt to obtain signed client certificate the same way the CertHandler would: if a signed cert
        // already exists in the stores directory use it, otherwise request it from the CA server
        if (!Files.exists(clientCrtFile)) {
            requestClientCert(clientCsrFile); // send the csr to the flask server to attempt to get client.crt and intermediate.crt
        }

        PrivateKey clientPrivKey = loadKeyFromPkcs8(clientPrivateKeyFile); // call method to load the private key of the client

        // certificate chain will flow back up to the root authority to verify if a certificate during the handshake is valid and trusted
        List<X509Certificate> certChain;
        try (InputStream inp = Files.newInputStream(clientCrtFile)) {
            certChain = new ArrayList<>(loadCertificateChain(inp)); // make mutable
        }

        X509Certificate intermediateCert = loadCertificate(intermediateCrtFile);

        // ensure intermediate is included after the leaf
        boolean hasIntermediate = certChain.stream()
            .anyMatch(c -> c.getSubjectX500Principal().equals(intermediateCert.getSubjectX500Principal()));
        if (!hasIntermediate) {
            certChain.add(intermediateCert);
        }

        KeyStore clientKeyStore = KeyStore.getInstance("JKS");

        // load existing keystore if it exists, else create new
        Path ksPath = Paths.get(DataManager.getDataPath("certs/client-keystore.jks"));
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                clientKeyStore.load(in, pass.toCharArray());
            }
        } else {
            clientKeyStore.load(null, null);
            System.err.println("Creating new keystore at " + ksPath);
        }

        // store private key
        clientKeyStore.setKeyEntry(
            "client",
            clientPrivKey,
            pass.toCharArray(),
            certChain.toArray(new X509Certificate[0])
        );

        // save back to same path
        try (OutputStream out = Files.newOutputStream(ksPath)) {
            clientKeyStore.store(out, pass.toCharArray());
        }

    }

    private static void requestClientCert(Path clientCsrFile) throws Exception {
        Path ksPath = Paths.get(DataManager.getDataPath("certs/client-keystore.jks"));
        Path tsPath = Paths.get(DataManager.getDataPath("client-truststore.jks"));

        String boundary = "----Boundary" + System.currentTimeMillis();
        String serverIp = System.getProperty("server.ip.address");
        if (serverIp == null || serverIp.isEmpty()) {
            serverIp = "127.0.0.1"; // fallback
        }

        URI flaskServURI = new URI("https://" + serverIp + ":5000/sign");
        HttpsURLConnection flaskServConn = (HttpsURLConnection) flaskServURI.toURL().openConnection();
        SSLContext ctx = buildSSLContext(tsPath, "changeit");
        flaskServConn.setSSLSocketFactory(ctx.getSocketFactory());
        flaskServConn.setDoOutput(true);
        flaskServConn.setRequestMethod("POST");
        flaskServConn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

        try (OutputStream o = flaskServConn.getOutputStream();
             PrintWriter w = new PrintWriter(new OutputStreamWriter(o, StandardCharsets.UTF_8), true)) {

            w.append("--").append(boundary).append("\r\n");
            w.append("Content-Disposition: form-data; name=\"csr\"; filename=\"client.csr\"\r\n");
            w.append("Content-Type: application/octet-stream\r\n\r\n");
            w.flush();

            Files.copy(clientCsrFile, o);
            o.flush();

            w.append("\r\n--").append(boundary).append("--\r\n");
            w.flush();
        }

        if (flaskServConn.getResponseCode() != 200) {
            String errMsg = "";
            try (InputStream err = flaskServConn.getErrorStream()) {
                if (err != null) errMsg = new String(err.readAllBytes(), StandardCharsets.UTF_8);
            }
            throw new IOException("Failed to receive certificate. HTTP " + flaskServConn.getResponseCode() + ": " + errMsg);
        }

        try (InputStream inp = flaskServConn.getInputStream()) {
            String pemPK = new String(inp.readAllBytes(), StandardCharsets.UTF_8);
            int splitIndex = pemPK.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length();
            String clientPem = pemPK.substring(0, splitIndex);
            String intermediatePem = pemPK.substring(splitIndex).trim();

            System.out.println(clientPem);
            System.out.println(intermediatePem);

            Files.writeString(Paths.get(DataManager.getDataPath("client.crt")), clientPem, StandardCharsets.UTF_8);
            Files.writeString(Paths.get(DataManager.getDataPath("intermediate.crt")), intermediatePem, StandardCharsets.UTF_8);
        }

    }

    private static SSLContext buildSSLContext(Path truststorePath, String password) throws KeyStoreException, NoSuchAlgorithmException {
        char[] pass = password.toCharArray();
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(truststorePath)) {
                trustStore.load(in, pass);
            } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            return sslContext;
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public static void updateCerts() throws Exception {
        // delete ks and ts if exists
        Files.deleteIfExists(Paths.get(DataManager.getDataPath("client-keystore.jks")));
        Files.deleteIfExists(Paths.get(DataManager.getDataPath("client-truststore.jks")));
        Files.deleteIfExists(Paths.get(DataManager.getDataPath("client.crt")));
        Files.deleteIfExists(Paths.get(DataManager.getDataPath("intermediate.crt")));

        String csrPEM = generateCsr();
        Path csrPath = Paths.get(DataManager.getDataPath("client.csr"));
        Files.writeString(csrPath, csrPEM, StandardCharsets.UTF_8);

        importCATruststore();
        requestClientCert(csrPath);
    }

    private static void importCATruststore() throws Exception {
        // rootCert sits in project root at certs/rootCert.crt (NOT in data path)
        Path rootCrtPath = Paths.get(certificatesDirectory, "rootCert.crt");
        if (!Files.exists(rootCrtPath)) {
            rootCrtPath = Paths.get(certificatesDirectory, "rootCert.pem");
        }
        if (!Files.exists(rootCrtPath)) {
            throw new FileNotFoundException("rootCert not found in " + certificatesDirectory);
        }

        X509Certificate rootCert;
        try (InputStream in = Files.newInputStream(rootCrtPath)) {
            rootCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, "changeit".toCharArray());
        trustStore.setCertificateEntry("rootCA", rootCert);

        // truststore goes in data path
        Path trustPath = Paths.get(DataManager.getDataPath("client-truststore.jks"));
        try (OutputStream out = Files.newOutputStream(trustPath)) {
            trustStore.store(out, "changeit".toCharArray());
        }
    }

    private PrivateKey loadKeyFromPkcs8(Path keyPath) throws Exception {
        String pemPK = Files.readString(keyPath, StandardCharsets.US_ASCII).trim();
        String base64 = pemPK.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        byte[] pkBytes = Base64.getDecoder().decode(base64); // decode private key bytes from pkcs8.key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private List<X509Certificate> loadCertificateChain(InputStream inp) throws Exception {
        String pemPK = new String(inp.readAllBytes(), StandardCharsets.UTF_8);
        Pattern pemSections = Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");
        Matcher matcher = pemSections.matcher(pemPK);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();

        while (matcher.find()) {
            try (InputStream bis = new ByteArrayInputStream(matcher.group().getBytes(StandardCharsets.UTF_8))) {
                certs.add((X509Certificate) certFactory.generateCertificate(bis));
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
        Path passPath = Path.of(DataManager.getDataPath("certs/keystorePass.txt"));
        Path jksPath = Path.of(DataManager.getDataPath("certs/client-keystore.jks"));
        if (!Files.exists(passPath)) throw new FileNotFoundException(passPath + " not found");
        if (!Files.exists(jksPath)) throw new FileNotFoundException(jksPath + " not found");

        // Get the current keystore with the dummy cert
        char[] pass = Files.readString(passPath).trim().toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(jksPath)) {
            ks.load(in, pass);
        }

        // Get the private key from that keystore entry
        String alias = "client";
        Key key = ks.getKey(alias, pass);
        if (key == null) throw new KeyStoreException("No private key for alias '" + alias + "'");
        PrivateKey priv = (PrivateKey) key;

        // Get the public key from the dummy cert
        X509Certificate dummy = (X509Certificate) ks.getCertificate(alias);
        if (dummy == null) throw new KeyStoreException("No certificate for alias '" + alias + "'");
        PublicKey pub = dummy.getPublicKey();

        // Start building the CSR, starting with the SAN
        String fqdn;
        String host;
        String systemIp = System.getProperty("server.ip.address");

        if (systemIp != null && !systemIp.isEmpty()) {
            // ip hostname from system props
            fqdn = systemIp;
            host = systemIp;
        } else {
            // localhost fallback
            fqdn = "localhost";
            host = "localhost";
            System.err.println("WARN: sys prop 'server.ip.address' not set, defaulting to 'localhost'.");
        }

        java.util.LinkedHashSet<GeneralName> sans = new java.util.LinkedHashSet<>();
        sans.add(new GeneralName(GeneralName.dNSName, host));
        sans.add(new GeneralName(GeneralName.dNSName, fqdn));
        sans.add(new GeneralName(GeneralName.dNSName, "localhost"));
        sans.add(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));

        // Get all the IP addresses on the machine's NICs (IPv4 only)
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

        // Building the subject
        X500Name subject = new X500Name("C=IE,O=Group-H Security,CN=" + fqdn);
        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(subject, pub); // Initiate the CSR, with the subject and public key

        // Setting the CSR extensions ie. permissions
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(sans.toArray(new GeneralName[0])));
        extGen.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        extGen.addExtension(Extension.extendedKeyUsage, true,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        // Signing the CSR using SHA256 to confirm the csr isn't edited after creation. That hash is signed with the private key.
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(priv);
        PKCS10CertificationRequest csr = builder.build(signer);

        // Write the CSR out as PEM and return it
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(csr);
        }
        return sw.toString();
    }

    public static void main(String[] args) throws Exception {
        updateCerts();
    }

}
