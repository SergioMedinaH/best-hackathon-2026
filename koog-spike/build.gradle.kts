// Standalone Gradle build to validate that Koog can talk to OpenAI from
// JVM/Kotlin code. Kept separate from the IntelliJ plugin so a Koog failure
// cannot break the plugin baseline.
//
// Run with:   ./gradlew run
// Needs:      OPENAI_API_KEY set in the environment

plugins {
    kotlin("jvm") version "2.3.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Koog — JetBrains Kotlin-native AI agent framework
    // Docs: https://docs.koog.ai/
    implementation("ai.koog:koog-agents:0.7.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    runtimeOnly("ch.qos.logback:logback-classic:1.5.18")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.hackathon.koogspike.MainKt")
}
