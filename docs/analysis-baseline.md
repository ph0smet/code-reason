# Analysis result fixture baseline

This is a reproducible smoke baseline for the analysis-result contract. It is not a precision/recall or large-project performance benchmark.

From the repository root, run:

```sh
./gradlew test --tests io.github.blindhacker99.codereason.AnalysisResultsIntegrationTest --no-daemon
rg BASELINE_JSON build/test-results/test/TEST-io.github.blindhacker99.codereason.AnalysisResultsIntegrationTest.xml
git rev-parse HEAD
java -version
```

The `BASELINE_JSON` record reports graph node/call counts, forward DFG reachability and recognized gaps, and elapsed milliseconds for analysis, traversal and a no-path trace. The test also asserts that the unrelated source and sink never produce a fabricated evidence chain, a bounded query reports truncation, an ambiguous source line requires an explicit node ID, and an unresolved call dead end is visible.

For comparisons, run the same command on the same machine and JDK with the same Gradle-resolved CPG snapshot. Record both cold and warm runs; timings from this tiny fixture are diagnostic only. CPG `main-SNAPSHOT` can change without a source edit, so retain the resolved dependency artifacts or checksums alongside any published measurement. A real-project benchmark still needs a separate corpus with labeled positive and negative flows, framework entrypoints, analysis time, memory, and agent tool cost.
