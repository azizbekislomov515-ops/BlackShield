plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.scan"
}

dependencies {
    implementation(projects.core.scanner)
}
