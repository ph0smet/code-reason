plugins {
    kotlin("jvm") version "2.3.0"
    kotlin("plugin.serialization") version "2.3.0"
    application
}

group = "io.github.blindhacker99.codereason"
version = "0.1.0"

application {
    mainClass.set("io.github.blindhacker99.codereason.ApplicationKt")
    applicationDefaultJvmArgs = listOf("-Xss515m", "-Xmx8g")
}

repositories {
    mavenCentral()
    maven("https://central.sonatype.com/repository/maven-snapshots/") {
        name = "Central Portal Snapshots"
        mavenContent { snapshotsOnly() }
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

kotlin {
    compilerOptions {
        freeCompilerArgs = listOf(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=kotlin.uuid.ExperimentalUuidApi",
        )
    }
}

// CPG: temporarily pinned to main-SNAPSHOT until 11.x stable lands on Maven Central.
// Source: Sonatype Central Portal Snapshots (configured in repositories above).
val cpgVersion = "main-SNAPSHOT"

dependencies {
    // CPG
    implementation("de.fraunhofer.aisec:cpg-core:$cpgVersion")
    implementation("de.fraunhofer.aisec:cpg-analysis:$cpgVersion")
    implementation("de.fraunhofer.aisec:cpg-concepts:$cpgVersion")
    runtimeOnly("de.fraunhofer.aisec:cpg-language-java:$cpgVersion")
    runtimeOnly("de.fraunhofer.aisec:cpg-language-python:$cpgVersion")

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
    maxHeapSize = "4g"
}
