

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

tasks.named("run") {
    dependsOn("makeClientKeystore")
}










