import java.net.Socket
import org.gradle.api.tasks.JavaExec

plugins {
    java
    application
    id("grouph.make-client-keystore")
}

application {
    mainClass.set("grouph.Main")
}

group = "grouph"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}

tasks.test {
    useJUnitPlatform()
}

tasks.named<JavaExec>("run") {
    dependsOn("obtainClientCert")
    standardInput = System.`in`

    val envServerIp = System.getenv("SERVER_IP") ?: "localhost"
    systemProperty("server.ip.address", envServerIp)
}

// like the 4th copy of this but sure
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

val obtainClientCert by tasks.registering(JavaExec::class) {
    group = "certs"

    mainClass.set("grouph.CertificateManager")
    classpath = sourceSets["main"].runtimeClasspath

    onlyIf {
        val certsDir = file(getDataPath("certs"))
        val ksPath = file(getDataPath("certs/client-keystore.jks"))
        val tsPath = file(getDataPath("client-truststore.jks"))

        val missing = !(certsDir.exists() && ksPath.exists() && tsPath.exists())
        if (!missing) println("all certs exist")
        missing
    }

    dependsOn("makeClientKeystore")
}













