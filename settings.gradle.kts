rootProject.name = "clawd-spy"

includeBuild("../cpg") {
    dependencySubstitution {
        substitute(module("de.fraunhofer.aisec:cpg-core")).using(project(":cpg-core"))
        substitute(module("de.fraunhofer.aisec:cpg-analysis")).using(project(":cpg-analysis"))
        substitute(module("de.fraunhofer.aisec:cpg-concepts")).using(project(":cpg-concepts"))
        substitute(module("de.fraunhofer.aisec:cpg-language-java")).using(project(":cpg-language-java"))
        substitute(module("de.fraunhofer.aisec:cpg-language-python")).using(project(":cpg-language-python"))
    }
}
