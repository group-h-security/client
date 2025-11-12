package grouph.cert

import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

class MakeClientKeystorePlugin : Plugin<Project> {
    override fun apply(project: Project) {
        project.tasks.register("makeClientKeystore") {
            group = "certs"
            doLast {
                val storesDir = project.file("stores")
                storesDir.mkdirs()

                val password = Base64.getEncoder().encodeToString(SecureRandom().generateSeed(24))
                project.file("stores/keystorePass.txt").writeText(password)

                if (Security.getProvider("BC") == null) {
                    Security.addProvider(BouncyCastleProvider())
                }

                val keyGen = KeyPairGenerator.getInstance("RSA", "BC")
                keyGen.initialize(4096)
                val keyPair = keyGen.generateKeyPair()

                val privateKeyBytes = keyPair.private.encoded
                val privateKeyPem = buildString {
                    appendLine("-----BEGIN PRIVATE KEY-----")
                    appendLine(Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(privateKeyBytes))
                    appendLine("-----END PRIVATE KEY-----")
                }
                project.file("stores/client-key.pem").writeText(privateKeyPem)
                println("✓ Private key written to stores/client-key.pem")

                val now = Date()
                val until = Date(now.time + 24L * 60 * 60 * 1000)
                val subject = X500Name("C=IE, O=Group-H Security, CN=temporary")
                val serial = BigInteger(64, SecureRandom())

                val certBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                    subject, serial, now, until, subject, keyPair.public
                )
                val signer = JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.private)
                val cert: X509Certificate = JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer))

                val ks = KeyStore.getInstance("JKS")
                ks.load(null, password.toCharArray())
                ks.setKeyEntry("client", keyPair.private, password.toCharArray(), arrayOf(cert))
                FileOutputStream(project.file("stores/client-keystore.jks")).use {
                    ks.store(it, password.toCharArray())
                }

                println("✓ Client keystore created (stores/client-keystore.jks)")
            }
        }
    }
}
