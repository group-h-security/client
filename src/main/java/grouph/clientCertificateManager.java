package grouph;

import java.security.KeyStore;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.util.ArrayList;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.io.*;
import java.net.URI;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.HttpURLConnection;
import java.security.cert.CertificateFactory;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class clientCertificateManager {//handle certs and stores

    private static final String certificatesDirectory = "certs";//pointer to certs directory
    private static final String pass = "cpass";//need to change to matchW

    public void start() throws Exception {
        //declare paths to make life easier
        Path clientPrivateKeyFile = Paths.get(certificatesDirectory, "c-pkcs8.key");
        Path clientCsrFile = Paths.get(certificatesDirectory, "client.csr");
        Path clientCrtFile = Paths.get(certificatesDirectory, "client.crt");
        Path intermediateCrtFile = Paths.get(certificatesDirectory, "intermediate.crt");
        //Path rootCrtFile = Paths.get(certificatesDirectory, root.crt); //needs to be added in

        certificatesRequest(clientCsrFile, clientCrtFile);//sedn the csr to the flask server to attempt to get client.crt and intermediate.crt

        PrivateKey clientPrivKey = loadKeyFromPkcs8(clientPrivateKeyFile);//call method to load the private key of the client
        //certificate chain will flow back up to the root authority to verify if a certificate during the handshake is valid and trusted
        List<X509Certificate> certChain;
        try (InputStream inp = Files.newInputStream(clientCrtFile)) {
            certChain = loadCertificateChain(inp);
        }

        X509Certificate intermediateCsr = loadCertificate(intermediateCrtFile);

        KeyStore clienKeyStore = KeyStore.getInstance("JKS");//need to put intermediate crt
        clienKeyStore.load(null, null);
        clienKeyStore.setKeyEntry( "owner", clientPrivKey, pass.toCharArray(),certChain.toArray(new X509Certificate[0])
        );
        try (FileOutputStream out = new FileOutputStream(certificatesDirectory + "/c-KeyStore.jks")) {
            clienKeyStore.store(out, pass.toCharArray());
        }

        KeyStore clientTrustStore = KeyStore.getInstance("JKS");
        clientTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry("rootCrt", intermediateCsr);//need to make sure it matches when added
        try (FileOutputStream out = new FileOutputStream(certificatesDirectory + "/c-TrustStore.jks")) {
            clientTrustStore.store(out, pass.toCharArray());
        }
        System.out.println("Clients keystore and truststore made without issue!");
        }

            private void certificatesRequest(Path clientCsrFile, Path outputCertPath) throws Exception {
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

            Files.writeString(Paths.get(certificatesDirectory, "client.crt"), clientPem, StandardCharsets.UTF_8);
            Files.writeString(Paths.get(certificatesDirectory, "intermediate.crt"), intermediatePem, StandardCharsets.UTF_8);
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
}
