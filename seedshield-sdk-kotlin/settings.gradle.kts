pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = ("seedauth-sdk-kotlin")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

include(
    "demo-app",
    "sdk-core",
    "sdk-compose"
)
