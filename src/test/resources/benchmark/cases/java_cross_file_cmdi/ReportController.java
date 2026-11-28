package fixtures.tier3.cmdi;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Tier 3 fixture: cross-file CMDi via Spring controller → report generator.
 * Source enters as a @RequestParam — a common Spring pattern.
 * The Runtime.exec() sink is reached through the call chain.
 */
@Controller
public class ReportController {

    private final ReportGenerator reportGenerator = new ReportGenerator();

    @GetMapping("/report")
    @ResponseBody
    public String generateReport(@RequestParam("format") String format) throws Exception {
        // SOURCE: user-controlled format parameter (e.g., "pdf", "csv")
        // Intended to select report type, but passed unsanitized downstream
        return reportGenerator.generate(format);
    }
}
