plugins {
    application
}

application {
    mainClass.set("io.github.authdiff.cli.AuthDiffCli")
}

dependencies {
    implementation(project(":core"))
    implementation("info.picocli:picocli:4.7.6")
    annotationProcessor("info.picocli:picocli-codegen:4.7.6")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.assertj:assertj-core:3.25.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
