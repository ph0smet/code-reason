# Program analysis for your coding agents.

[![CI](https://github.com/blindhacker99/code-reason/actions/workflows/ci.yml/badge.svg)](https://github.com/blindhacker99/code-reason/actions/workflows/ci.yml)

> *Instead of grep-and-guess, provide your agents program analysis capabilities with code-reason.*

**code-reason** is an MCP server that gives coding agents real program-analysis primitives — data-flow reachability, call-graph traversal, evidence-chain construction — so they verify code behavior from ground truth instead of speculation.

## Why code-reason

Coding agents are good at reading code, but they struggle with whole-program questions:

- *Does user-controlled input actually reach this SQL call, or does sanitization cut the flow off?*
- *Who really invokes this function across the codebase?*
- *What is the complete evidence chain from source to sink?*

Without a code-analysis tool, the agent answers these by **manual grep-based tracing.** It can read code, but it can't actually trace data flow, walk a control graph, or verify that user input reaches a sink. Ask any modern coding agent how it traces taint without a tool, and the answer is some variant of *"I read files and follow string matches."*

That works for simple cases. The cracks show on anything non-trivial — aliased variables, inter-procedural flow, sanitization checks, framework-injected inputs. The agent still produces an answer, often with high confidence, but it's reading 6+ files to confirm a single chain, burning context on speculation, and silently missing flows it never thought to grep for. For security-sensitive work, a confident wrong answer is more dangerous than no answer at all — and that's exactly what grep-based tracing produces at scale.

code-reason closes the gap. The agent stays in charge of *what's interesting*; code-reason answers *what's actually true* — backed by a code property graph parsed once and queried cheaply. The result: agents that are more deterministic, more token-efficient, and faster — and agentic security workflows you can actually trust.

Where traditional SAST tools produce findings reports for humans to triage, code-reason exposes the underlying analysis primitives for an agent to drive its own investigation.

Built on [Fraunhofer AISEC's Code Property Graph](https://github.com/Fraunhofer-AISEC/cpg) for multi-language data-flow, control-flow, and taint analysis, and the [Kotlin MCP SDK](https://github.com/modelcontextprotocol/kotlin-sdk) to expose those capabilities as agent-callable tools.

## What you get

From dogfood sessions on real Java and Python codebases:

- **30-40% fewer agent tokens** on multi-step security reviews, mostly from call-graph queries that would otherwise take 5-10 grep iterations to confirm by hand.
- **Compact structured answers, not file dumps.** A call-graph query returns reachable methods in JSON; the grep-and-read equivalent forces the agent to read 6+ files to confirm one chain.
- **One analysis pass per service, unlimited queries.** `reason_analyze_project` builds the CPG once; every other `reason_*` tool queries it cheaply.
- **Real evidence chains.** `reason_trace_taint_path` returns the full source-to-sink path with intermediate steps and code context — not "looks like SQLi maybe."

## How it works

code-reason sits between the coding agent and a code property graph. The agent drives — code-reason answers.

```
   Coding agent (Claude Code, Cursor, ...)
              │  MCP over stdio
              ▼
       code-reason server
              │
              ▼
   Fraunhofer CPG (Java + Python frontends)
              │
              ▼
        Target codebase
```

A typical loop runs in three phases:

1. **Analyze.** The agent calls `reason_analyze_project`. CPG parses the target codebase into a multi-graph: abstract syntax, control flow, data flow, and evaluation order — all in one queryable structure.

2. **Query.** The agent calls one or more `reason_*` tools, each of which translates to a focused graph operation: taint propagation, call-graph traversal, data-flow reachability, evidence-chain construction.

3. **Reason.** Each tool returns a structured result (locations, paths, confidence, evidence). The agent combines those results with its own contextual reasoning and decides what to ask next.

The agent provides the *intent* and high-level reasoning; code-reason provides *ground-truth answers* against the actual graph. No grep-and-guess, no oversized context dumps.

## Tools

code-reason exposes nine MCP tools, grouped by purpose:

| Group | Tool | Purpose |
|---|---|---|
| Setup | `reason_analyze_project` | Parse a project into a code property graph |
| Navigation | `reason_find_entry_points` | Locate HTTP handlers, CLI entries, framework hooks |
| Navigation | `reason_find_callers` | "Who calls this function?" |
| Navigation | `reason_find_callees` | "What does this function call?" |
| Data flow | `reason_query_dataflow` | Forward/backward reachability over the data-flow graph |
| Data flow | `reason_trace_taint_path` | Full source-to-sink evidence chain between any two points |
| Catalog scan (convenience) | `reason_scan_injections` | Catalog-driven taint analysis (SQLi/XSS/command injection) |
| Catalog scan (convenience) | `reason_list_supported_checks` | Enumerate built-in vulnerability checks |
| Catalog scan (convenience) | `reason_get_finding_detail` | Description + remediation for a scan finding |

The marquee value is the **navigation** and **data flow** primitives — the agent composes them to answer whole-program questions on its own. The **catalog scan** tools are a convenience baseline for quick first-pass triage; the agent's own reasoning over the primitives is what makes the difference on real codebases.

## Prerequisites

- JDK 21

The build pulls CPG artifacts from Maven Central and Sonatype Central Snapshots (the latter for `main-SNAPSHOT` until CPG 11.x lands as a stable release on Central). No sibling checkouts required.

## Build

```
./gradlew installDist
```

The launcher lands at `build/install/code-reason/bin/code-reason`.

## Running tests

```
./gradlew test
```

Integration tests run the full pipeline against small Java and Python fixtures.

## Claude Code setup

Add code-reason to your `.mcp.json` (project-scoped) or `~/.claude/.mcp.json` (global):

```json
{
  "mcpServers": {
    "code-reason": {
      "command": "/absolute/path/to/build/install/code-reason/bin/code-reason",
      "args": ["--stdio"]
    }
  }
}
```

Restart Claude Code; the `reason_*` tools will appear in its tool list.

## Example workflow

A typical agent-driven session — primitives composing into evidence:

1. Agent calls `reason_analyze_project` to build the CPG.
2. Agent calls `reason_find_entry_points` to enumerate where external input enters the codebase.
3. For a suspicious entry point, agent uses `reason_find_callees` and `reason_query_dataflow` to map the downstream reach.
4. When the data reaches a sensitive call, agent calls `reason_trace_taint_path` for the full source-to-sink evidence chain.
5. Agent reasons about exploitability from the structured result and decides what to investigate next.

For quick first-pass triage, the agent can also call `reason_scan_injections` to surface candidate flows from the built-in catalog, then verify each one with `reason_trace_taint_path`.

## Supported languages

- Java
- Python

Additional CPG frontends (C/C++, Go, TypeScript, JVM, LLVM, Ruby) can be enabled by adding the corresponding `cpg-language-*` dependency in `build.gradle.kts`.

## Status

code-reason is v0.1.0 — early, research-grade. CI runs on every push and pull request. The build is currently pinned to CPG `main-SNAPSHOT`; this will move to a stable `11.x` release once Fraunhofer publishes one to Maven Central.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

## Acknowledgments

Built on [Fraunhofer AISEC's Code Property Graph](https://github.com/Fraunhofer-AISEC/cpg).
