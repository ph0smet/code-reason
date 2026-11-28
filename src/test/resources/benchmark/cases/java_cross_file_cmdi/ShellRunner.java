package fixtures.tier3.cmdi;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Utility that executes shell commands.
 * From this file alone, the run() method looks like a generic utility.
 * Only cross-file taint analysis reveals that 'arg' originates from an HTTP parameter.
 */
public class ShellRunner {

    public String run(String script, String arg) throws Exception {
        // SINK: arg is concatenated into a shell command and executed
        // arg originated from @RequestParam("format") in ReportController — two hops away
        Process process = Runtime.getRuntime().exec(new String[]{"bash", script, arg});

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}
