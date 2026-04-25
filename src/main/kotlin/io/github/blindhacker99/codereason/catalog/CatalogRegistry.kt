package io.github.blindhacker99.codereason.catalog

import io.github.blindhacker99.codereason.catalog.java.JavaCmdiCatalog
import io.github.blindhacker99.codereason.catalog.java.JavaSqliCatalog
import io.github.blindhacker99.codereason.catalog.java.JavaXssCatalog
import io.github.blindhacker99.codereason.catalog.python.PythonCmdiCatalog
import io.github.blindhacker99.codereason.catalog.python.PythonSqliCatalog
import io.github.blindhacker99.codereason.catalog.python.PythonXssCatalog

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
