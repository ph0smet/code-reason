package fixtures.tier3.cmdi;

/**
 * Report generation service.
 * Delegates actual rendering to a shell script — passes format unsanitized.
 */
public class ReportGenerator {

    private final ShellRunner shellRunner = new ShellRunner();

    public String generate(String format) throws Exception {
        // format came from HTTP — still tainted, still no sanitization
        String scriptPath = "/usr/local/bin/render-report.sh";
        return shellRunner.run(scriptPath, format);
    }
}
