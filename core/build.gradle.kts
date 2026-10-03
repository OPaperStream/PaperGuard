// The PaperGuard format as a small library without dependencies, for proxies and backends.
java {
    withSourcesJar()
    withJavadocJar()
}

base {
    archivesName.set("paperguard-core")
}

dependencies {
    testImplementation("com.google.code.gson:gson:2.11.0")
}
