dependencies {
    implementation(project(":core"))
    // Oldest API PaperGuard supports; it runs unchanged on every newer Paper and on Folia.
    compileOnly("com.destroystokyo.paper:paper-api:1.12.2-R0.1-SNAPSHOT")
}

tasks {
    processResources {
        val version = project.version.toString()
        inputs.property("version", version)
        filesMatching("plugin.yml") {
            expand("version" to version)
        }
    }
    jar {
        archiveBaseName.set("PaperGuard")
        // The core library is small and has no dependencies, so it goes straight in.
        from(project(":core").sourceSets.main.get().output)
    }
}
