pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "BlackShield"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

include(":core:scanner")
include(":core:data")
include(":core:network")
include(":feature:scan")
include(":feature:protection")
include(":feature:webshield")
include(":feature:settings")
