dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation(project(":core"))

    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.assertj:assertj-core:3.25.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.jar {
    dependsOn(":core:jar")
    archiveFileName.set("authdiff-burp-all.jar")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}
