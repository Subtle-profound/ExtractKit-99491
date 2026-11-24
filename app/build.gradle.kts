plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

android {
    namespace = "com.extractkit.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.extractkit.app"
        minSdk = 31
        targetSdk = 35
        versionCode = 633
        versionName = "9.444"
        resourceConfigurations += listOf("zh", "en")

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
 isMinifyEnabled = true           // R8, Compose included
 isShrinkResources = true         // drop unused resources
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
        aidl = true
    }
    sourceSets {
        getByName("main").java.srcDirs("src/main/kotlin")
    }
    androidResources {
        noCompress += listOf("ek-core-uid0", "ek-core-android")
    }
    lint {
 // AGP 8.7 lint crashes on Kotlin 2.4; release lint is disabled
        checkReleaseBuilds = false
        abortOnError = false
    }

    packaging {
        jniLibs.useLegacyPackaging = false
        resources {
 // keep the unpacked native lib out; assets carry it as .gz
            excludes += "assets/ekcalib/libekcalib.so"
            excludes += setOf(
                "META-INF/*.version",
                "META-INF/*.kotlin_module",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "DebugProbesKt.bin",
                "kotlin/**",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    // 9.411: pure-java zstd for whole-file compressed boot.img (no JNI)
    implementation("io.airlift:aircompressor:0.27")

 // local liquid-glass module (Kyant backdrop, see :glass)
    implementation(project(":glass"))
    implementation("androidx.compose.ui:ui:1.9.0")
    implementation("androidx.compose.foundation:foundation:1.9.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.compose.material3:material3:1.3.2")
    implementation("androidx.activity:activity-compose:1.9.3")
    configurations.all {
        resolutionStrategy {
            force("androidx.compose.ui:ui:1.9.0")
            force("androidx.compose.ui:ui-graphics:1.9.0")
            force("androidx.compose.runtime:runtime:1.9.0")
            force("androidx.compose.foundation:foundation:1.9.0")
        }
    }

 // JVM unit tests: BTF / kallsyms / plain-Android-free helpers
    testImplementation("junit:junit:4.13.2")
}
