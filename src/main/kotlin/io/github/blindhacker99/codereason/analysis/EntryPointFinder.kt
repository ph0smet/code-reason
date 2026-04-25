package io.github.blindhacker99.codereason.analysis

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.graph.declarations.Method
import de.fraunhofer.aisec.cpg.graph.declarations.Record
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.graph.records
import kotlinx.serialization.Serializable

@Serializable
data class EntryPoint(
    val functionName: String,
    val file: String?,
    val line: Int?,
    val type: String,
    val framework: String?,
    val httpMethod: String?,
    val route: String?,
    val parameters: List<EntryPointParam>,
)

@Serializable
data class EntryPointParam(
    val name: String,
    val type: String?,
    val source: String?,
)

class EntryPointFinder(private val result: TranslationResult) {

    fun findEntryPoints(filter: String? = null): List<EntryPoint> {
        val entries = mutableListOf<EntryPoint>()

        entries.addAll(findJavaHttpHandlers())
        entries.addAll(findPythonHttpHandlers())
        entries.addAll(findMainMethods())

        return when (filter?.lowercase()) {
            "http" -> entries.filter { it.type == "http_handler" }
            "cli" -> entries.filter { it.type == "main" }
            "all", null -> entries
            else -> entries
        }
    }

    private fun findJavaHttpHandlers(): List<EntryPoint> {
        val entries = mutableListOf<EntryPoint>()

        for (func in result.functions) {
            // Spring annotations
            val springEntry = detectSpringHandler(func)
            if (springEntry != null) {
                entries.add(springEntry)
                continue
            }

            // Servlet overrides (doGet, doPost, etc.)
            val servletEntry = detectServletHandler(func)
            if (servletEntry != null) {
                entries.add(servletEntry)
                continue
            }

            // JAX-RS annotations
            val jaxrsEntry = detectJaxRsHandler(func)
            if (jaxrsEntry != null) {
                entries.add(jaxrsEntry)
                continue
            }
        }

        return entries
    }

    private fun detectSpringHandler(func: Function): EntryPoint? {
        val springMappings = mapOf(
            "RequestMapping" to null,
            "GetMapping" to "GET",
            "PostMapping" to "POST",
            "PutMapping" to "PUT",
            "DeleteMapping" to "DELETE",
            "PatchMapping" to "PATCH",
        )

        for (annotation in func.annotations) {
            val annotName = annotation.name.localName
            val httpMethod = springMappings[annotName]
            if (httpMethod != null || annotName == "RequestMapping") {
                val route = extractAnnotationValue(annotation, "value")
                    ?: extractAnnotationValue(annotation, "path")
                    ?: extractAnnotationDefaultValue(annotation)

                val resolvedMethod = httpMethod
                    ?: extractAnnotationValue(annotation, "method")
                    ?: "ANY"

                return EntryPoint(
                    functionName = func.name.toString(),
                    file = func.location?.artifactLocation?.fileName,
                    line = func.location?.region?.startLine,
                    type = "http_handler",
                    framework = "spring",
                    httpMethod = resolvedMethod,
                    route = route,
                    parameters = extractParams(func, "spring"),
                )
            }
        }
        return null
    }

    private fun detectServletHandler(func: Function): EntryPoint? {
        val servletMethods = mapOf(
            "doGet" to "GET",
            "doPost" to "POST",
            "doPut" to "PUT",
            "doDelete" to "DELETE",
            "service" to "ANY",
        )

        val localName = func.name.localName
        val httpMethod = servletMethods[localName] ?: return null

        // Check if the function has HttpServletRequest parameter
        val hasServletParam = func.parameters.any { param ->
            val typeName = param.type.name.toString()
            typeName.contains("HttpServletRequest") || typeName.contains("ServletRequest")
        }

        if (!hasServletParam) return null

        return EntryPoint(
            functionName = func.name.toString(),
            file = func.location?.artifactLocation?.fileName,
            line = func.location?.region?.startLine,
            type = "http_handler",
            framework = "servlet",
            httpMethod = httpMethod,
            route = null,
            parameters = extractParams(func, "servlet"),
        )
    }

    private fun detectJaxRsHandler(func: Function): EntryPoint? {
        val jaxrsMappings = mapOf(
            "GET" to "GET",
            "POST" to "POST",
            "PUT" to "PUT",
            "DELETE" to "DELETE",
            "PATCH" to "PATCH",
        )

        for (annotation in func.annotations) {
            val annotName = annotation.name.localName
            val httpMethod = jaxrsMappings[annotName]
            if (httpMethod != null) {
                val pathAnnotation = func.annotations.find { it.name.localName == "Path" }
                val route = pathAnnotation?.let {
                    extractAnnotationDefaultValue(it)
                }

                return EntryPoint(
                    functionName = func.name.toString(),
                    file = func.location?.artifactLocation?.fileName,
                    line = func.location?.region?.startLine,
                    type = "http_handler",
                    framework = "jaxrs",
                    httpMethod = httpMethod,
                    route = route,
                    parameters = extractParams(func, "jaxrs"),
                )
            }
        }
        return null
    }

    private fun findPythonHttpHandlers(): List<EntryPoint> {
        val entries = mutableListOf<EntryPoint>()

        for (func in result.functions) {
            // Flask @app.route() decorator
            val flaskEntry = detectFlaskHandler(func)
            if (flaskEntry != null) {
                entries.add(flaskEntry)
                continue
            }

            // Django view detection (function-based views)
            val djangoEntry = detectDjangoHandler(func)
            if (djangoEntry != null) {
                entries.add(djangoEntry)
                continue
            }
        }

        return entries
    }

    private fun detectFlaskHandler(func: Function): EntryPoint? {
        for (annotation in func.annotations) {
            val annotName = annotation.name.toString()
            if (annotName.contains("route") || annotName.contains("app.route")) {
                val route = extractAnnotationDefaultValue(annotation)
                val methods = extractAnnotationValue(annotation, "methods")

                return EntryPoint(
                    functionName = func.name.toString(),
                    file = func.location?.artifactLocation?.fileName,
                    line = func.location?.region?.startLine,
                    type = "http_handler",
                    framework = "flask",
                    httpMethod = methods ?: "GET",
                    route = route,
                    parameters = extractParams(func, "flask"),
                )
            }
        }
        return null
    }

    private fun detectDjangoHandler(func: Function): EntryPoint? {
        // Django function-based views take (request, ...) as first param
        val params = func.parameters
        if (params.isEmpty()) return null

        val firstParam = params.first()
        val typeName = firstParam.type.name.toString()
        val paramName = firstParam.name.localName

        if (typeName.contains("HttpRequest") || paramName == "request") {
            // Check if there's a second param suggesting URL args (Django pattern)
            val hasUrlParams = params.size > 1 || paramName == "request"

            // Only flag as Django if the param is named "request" (convention)
            if (paramName != "request") return null

            return EntryPoint(
                functionName = func.name.toString(),
                file = func.location?.artifactLocation?.fileName,
                line = func.location?.region?.startLine,
                type = "http_handler",
                framework = "django",
                httpMethod = "ANY",
                route = null,
                parameters = extractParams(func, "django"),
            )
        }
        return null
    }

    private fun findMainMethods(): List<EntryPoint> {
        val entries = mutableListOf<EntryPoint>()

        for (func in result.functions) {
            val localName = func.name.localName
            if (localName == "main") {
                entries.add(
                    EntryPoint(
                        functionName = func.name.toString(),
                        file = func.location?.artifactLocation?.fileName,
                        line = func.location?.region?.startLine,
                        type = "main",
                        framework = null,
                        httpMethod = null,
                        route = null,
                        parameters = extractParams(func, null),
                    )
                )
            }
        }

        return entries
    }

    private fun extractParams(func: Function, framework: String?): List<EntryPointParam> {
        return func.parameters.map { param ->
            val source = classifyParamSource(param, framework)
            EntryPointParam(
                name = param.name.localName,
                type = param.type.name.toString(),
                source = source,
            )
        }
    }

    private fun classifyParamSource(
        param: de.fraunhofer.aisec.cpg.graph.declarations.Parameter,
        framework: String?,
    ): String? {
        // Check annotations for source classification
        for (annotation in param.annotations) {
            val annotName = annotation.name.localName
            return when (annotName) {
                "RequestParam", "QueryParam" -> "query"
                "PathVariable", "PathParam" -> "path"
                "RequestBody" -> "body"
                "RequestHeader", "HeaderParam" -> "header"
                "CookieValue", "CookieParam" -> "cookie"
                else -> null
            } ?: continue
        }

        // Infer from type for servlet
        if (framework == "servlet") {
            val typeName = param.type.name.toString()
            if (typeName.contains("HttpServletRequest")) return "request"
            if (typeName.contains("HttpServletResponse")) return "response"
        }

        return null
    }

    private fun extractAnnotationValue(
        annotation: de.fraunhofer.aisec.cpg.graph.Annotation,
        key: String,
    ): String? {
        val member = annotation.members.find { it.name.localName == key }
        return member?.value?.code?.removeSurrounding("\"")
    }

    private fun extractAnnotationDefaultValue(
        annotation: de.fraunhofer.aisec.cpg.graph.Annotation,
    ): String? {
        // Default value is typically the first member or "value" member
        val member = annotation.members.firstOrNull()
        return member?.value?.code?.removeSurrounding("\"")
    }
}
