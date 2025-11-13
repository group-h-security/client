package grouph.cert

import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File
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

    // everything we make should not sit in root of the project but sit in corresponding data section of the os
    // %APPDATA% for windows, Application Support for macos etc.
    private fun getDataPath(fileName: String): String {
        val os = System.getProperty("os.name").lowercase()
        val basePath: String = when {
            "win" in os -> {
                val appData = System.getenv("APPDATA")
                appData ?: System.getProperty("user.home")
            }
            "mac" in os -> System.getProperty("user.home") + "/Library/Application Support"
            else -> System.getProperty("user.home") + "/.local/share"
        }

        val dir = File(basePath, "grouph")
        if (!dir.exists()) dir.mkdirs()

        // ensure certs and stores subdirectories exist under the same data path
        val certsDir = File(dir, "certs")
        if (!certsDir.exists()) certsDir.mkdirs()

        return File(dir, fileName).absolutePath
    }

    override fun apply(project: Project) {
        project.tasks.register("makeClientKeystore") {
            group = "certs"
            doLast {
                val password = Base64.getEncoder().encodeToString(SecureRandom().generateSeed(24))
                File(getDataPath("certs/keystorePass.txt")).writeText(password)

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
                File(getDataPath("certs/client-key.pem")).writeText(privateKeyPem)
                println("✓ Private key written to ${getDataPath("certs/client-key.pem")}")

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
                FileOutputStream(File(getDataPath("certs/client-keystore.jks"))).use {
                    ks.store(it, password.toCharArray())
                }

                println("✓ Client keystore created (${getDataPath("certs/client-keystore.jks")})")
            }
        }
    }
}
