package dev.clawdspy.catalog.python

import dev.clawdspy.catalog.*
import dev.clawdspy.catalog.LanguageProfile.PYTHON
import dev.clawdspy.catalog.TaintKind.*
import dev.clawdspy.catalog.VulnClass.XSS

object PythonXssCatalog : SourceSinkCatalog {
    override val vulnClass = XSS
    override val language = PYTHON

    override val sources =
        listOf(
            TaintSpec(XSS, PYTHON, "flask.request.args.get", SOURCE, "Flask query parameter"),
            TaintSpec(XSS, PYTHON, "flask.request.form.get", SOURCE, "Flask form data"),
            TaintSpec(XSS, PYTHON, "django.http.request.HttpRequest.GET.get", SOURCE, "Django GET parameter"),
            TaintSpec(XSS, PYTHON, "django.http.request.HttpRequest.POST.get", SOURCE, "Django POST parameter"),
        )

    override val sinks =
        listOf(
            TaintSpec(XSS, PYTHON, "flask.render_template_string", SINK, "Flask render_template_string (unsafe)"),
            TaintSpec(XSS, PYTHON, "markupsafe.Markup", SINK, "MarkupSafe Markup (marks as safe)"),
            TaintSpec(XSS, PYTHON, "django.utils.safestring.mark_safe", SINK, "Django mark_safe"),
        )

    override val sanitizers =
        listOf(
            TaintSpec(XSS, PYTHON, "markupsafe.escape", SANITIZER, "MarkupSafe HTML escaping"),
            TaintSpec(XSS, PYTHON, "django.utils.html.escape", SANITIZER, "Django HTML escaping"),
        )
}
