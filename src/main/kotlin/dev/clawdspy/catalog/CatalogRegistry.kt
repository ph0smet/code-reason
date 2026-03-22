package dev.clawdspy.catalog

import dev.clawdspy.catalog.java.JavaCmdiCatalog
import dev.clawdspy.catalog.java.JavaSqliCatalog
import dev.clawdspy.catalog.java.JavaXssCatalog
import dev.clawdspy.catalog.python.PythonCmdiCatalog
import dev.clawdspy.catalog.python.PythonSqliCatalog
import dev.clawdspy.catalog.python.PythonXssCatalog

object CatalogRegistry {
    private val catalogs: List<SourceSinkCatalog> =
        listOf(
            JavaSqliCatalog,
            JavaXssCatalog,
            JavaCmdiCatalog,
            PythonSqliCatalog,
            PythonXssCatalog,
            PythonCmdiCatalog,
        )

    fun getCatalogs(
        vulnClass: VulnClass? = null,
        language: LanguageProfile? = null,
    ): List<SourceSinkCatalog> {
        return catalogs.filter {
            (vulnClass == null || it.vulnClass == vulnClass) &&
                (language == null || it.language == language)
        }
    }
}
