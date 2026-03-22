package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.passes.Description
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlin.reflect.KClass
import kotlin.reflect.KType
import kotlin.reflect.KTypeParameter
import kotlin.reflect.KTypeProjection
import kotlin.reflect.full.findAnnotations
import kotlin.reflect.full.memberProperties
import kotlinx.serialization.json.*

var globalAnalysisResult: TranslationResult? = null

var globalTranslationContext: de.fraunhofer.aisec.cpg.TranslationContext? = null

fun KType.toSchemaType(
    typeProjections: Map<KTypeParameter, KTypeProjection?>? = null
): Pair<String, (JsonObjectBuilder.() -> Unit)?> {
    typeProjections?.get(this.classifier)?.let {
        return it.type?.toSchemaType(typeProjections) ?: ("object" to null)
    }

    return when (val classifier = this.classifier) {
        String::class -> "string" to null
        Int::class, Long::class -> "integer" to null
        Float::class, Double::class -> "number" to null
        Boolean::class -> "boolean" to null
        Set::class, List::class ->
            "array" to {
                this@toSchemaType.arguments.singleOrNull()?.type?.let { itemType ->
                    putJsonObject("items") {
                        val (type, modifier) = itemType.toSchemaType()
                        put("type", type)
                        modifier?.invoke(this)
                    }
                }
            }
        else ->
            "object" to {
                (classifier as? KClass<*>)?.let { kClass ->
                    this.put("properties", kClass.toSchemaJson(this@toSchemaType.arguments))
                    putJsonArray("required") {
                        kClass.memberProperties.forEach { property ->
                            if (!property.returnType.isMarkedNullable) {
                                add(property.name)
                            }
                        }
                    }
                }
            }
    }
}

fun KClass<*>.toSchemaJson(typeProjections: List<KTypeProjection>? = null): JsonObject {
    return buildJsonObject {
        this@toSchemaJson.memberProperties.forEach { property ->
            val propertyName = property.name
            val paramToProjection =
                this@toSchemaJson.typeParameters
                    .mapIndexed { index, p -> p to typeProjections?.get(index) }
                    .toMap()
            val (propertyType, modifier) = property.returnType.toSchemaType(paramToProjection)
            val description = property.findAnnotations<Description>().firstOrNull()
            putJsonObject(propertyName) {
                put("type", propertyType)
                description?.let { put("description", it.briefDescription) }
                modifier?.invoke(this)
            }
        }
    }
}

fun KClass<*>.toSchema(): ToolSchema {
    val required = mutableListOf<String>()
    val properties = this.toSchemaJson()
    this@toSchema.memberProperties.forEach { property ->
        if (!property.returnType.isMarkedNullable) {
            required.add(property.name)
        }
    }
    return ToolSchema(properties = properties, required = required)
}

inline fun <reified T> JsonObject.toObject(): T =
    Json.decodeFromString<T>(Json.encodeToString(this))

inline fun <reified T> Server.addTool(
    name: String,
    description: String,
    noinline handler: (T) -> CallToolResult,
) {
    val inputSchema = T::class.toSchema()
    val parameters =
        inputSchema.properties
            ?.map { (k, v) ->
                val type = v.jsonObject["type"]?.jsonPrimitive?.content ?: "unknown"
                val desc = v.jsonObject["description"]?.jsonPrimitive?.content ?: ""
                "- $k: $desc"
            }
            ?.joinToString(separator = "\n", prefix = "$description\n\nParameters:\n") { it }
    this.addTool(
        name,
        description + (parameters ?: ""),
        inputSchema = inputSchema,
    ) { request ->
        try {
            val payload =
                request.arguments?.toObject<T>()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("Invalid or missing payload."))
                    )
            handler(payload)
        } catch (e: Exception) {
            CallToolResult(
                content = listOf(TextContent("Error: ${e.message ?: e::class.simpleName}"))
            )
        }
    }
}

fun requireAnalysisResult(): TranslationResult {
    return globalAnalysisResult
        ?: throw IllegalStateException(
            "No analysis result available. Please analyze your code first using spy_analyze_project."
        )
}
