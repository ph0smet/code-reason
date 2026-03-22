plugins {
    kotlin("jvm") version "2.3.0"
    kotlin("plugin.serialization") version "2.3.0"
    application
}

group = "dev.clawdspy"
version = "0.1.0"

application {
    mainClass.set("dev.clawdspy.ApplicationKt")
    applicationDefaultJvmArgs = listOf("-Xss515m", "-Xmx8g")
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    // CPG (resolved via composite build)
    implementation("de.fraunhofer.aisec:cpg-core")
    implementation("de.fraunhofer.aisec:cpg-analysis")
    implementation("de.fraunhofer.aisec:cpg-concepts")
    runtimeOnly("de.fraunhofer.aisec:cpg-language-java")
    runtimeOnly("de.fraunhofer.aisec:cpg-language-python")

    // MCP SDK
    implementation("io.modelcontextprotocol:kotlin-sdk:0.9.0")

    // Ktor (for SSE/HTTP transport)
    implementation("io.ktor:ktor-server-cio:3.4.0")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.4.0")

    // CLI
    implementation("info.picocli:picocli:4.7.0")
    annotationProcessor("info.picocli:picocli-codegen:4.7.0")

    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")

    // Logging
    implementation("org.apache.logging.log4j:log4j-slf4j2-impl:2.25.3")

    // Testing
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
