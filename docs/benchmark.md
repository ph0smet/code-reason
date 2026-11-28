# Labeled correctness and latency benchmark

Run the opt-in `benchmark` Gradle task to measure the same CPG analysis configuration used by `reason_analyze_project`, followed by catalog taint analysis. The task writes `build/reports/benchmark/results.json` and `results.md`. CI uploads both as the `code-reason-benchmark` artifact.

## Corpus and labels

The manifest is [`cases.json`](../src/test/resources/benchmark/cases.json). It contains 14 labeled cases across Java and Python: direct, helper, and cross-file SQL injection; command injection; XSS; parameterized-query negatives; and a constant-query negative. Two cross-file cases add 100 generated, harmless source files each, so the report includes correctness and latency at 102-103 files as well as small cases. The generated files are deterministic and created under `build/benchmark-generated` during the run.

The first six source cases were adapted from the earlier `clawd-spy-benchmarking` checkout. Their source and sink line labels were checked against the actual files; a few inherited ground-truth line numbers were stale. The additional cases and scale variants are in this repository. The manifest is authoritative for this benchmark.

A positive case is a true positive only if an **unsanitized** catalog finding matches both the labeled source and sink file and line. An incorrect or missing source-to-sink pair is a false negative, even if a different finding appears. Safe cases with any unsanitized finding are false positives. The report retains distinct unmatched source/sink locations and a raw finding count so duplicate catalog matches remain visible. Precision and recall are case-level metrics.

## Run locally

The Python frontend needs JEP 4.3.1 to match the CPG dependency, a native library path, and its Python module path. The following works on macOS and Linux with JDK 21 and a compatible Python installation:

```sh
python3 -m venv /tmp/code-reason-cpg-python
/tmp/code-reason-cpg-python/bin/pip install jep==4.3.1
site_packages=$(/tmp/code-reason-cpg-python/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
PYTHONPATH="$site_packages" JEP_LIBRARY_PATH="$site_packages/jep" ./gradlew benchmark --no-daemon
```

`-PjepLibraryPath=/path/to/site-packages/jep` can replace `JEP_LIBRARY_PATH`. The task fails if any case has a setup or analysis error, while preserving the JSON and Markdown report. It does **not** fail on a detection miss; the labels expose current accuracy and keep the benchmark useful while the analyzers improve.

The default `test` and `build` tasks exclude this benchmark. CI installs JEP separately and runs it on each pull request and main push.

## Baseline and limits

On macOS arm64, Java 21.0.10 and Python 3.14 with JEP 4.3.1, the initial run produced **10 TP, 1 FN, 1 FP, 2 TN, 0 errors**. The Java command-injection case is missed because the current Java catalog does not treat Spring `@RequestParam` as a source. The Python parameterized SQL query is reported because the current sink match treats data in the parameter tuple as if it tainted the SQL query string. Java cases also produce extra source locations at servlet method parameters; the report exposes these separately.

Latency is single-run wall clock time per case, split into CPG construction and catalog scan. Cases run in manifest order in one JVM, so class loading, JIT, cache state, and host resources affect numbers. Compare runs on the same host and inspect per-case times rather than interpreting the totals as steady-state throughput. Generated distractors test parser and graph scaling without modeling a real application. This curated corpus does not estimate accuracy on arbitrary projects or agent token savings.
