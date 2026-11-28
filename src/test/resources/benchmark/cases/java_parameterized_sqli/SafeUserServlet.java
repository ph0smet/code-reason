package fixtures.tier2.sqli_sanitizer_trap;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Tier 2 sanitizer trap: looks like the same pattern as t2-java-sqli-001
 * but uses PreparedStatement — no SQLi vulnerability.
 * Label: safe. A vulnerability finding here is a false positive.
 */
public class SafeUserServlet extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String username = req.getParameter("user");  // user-controlled input

        // Same structure: HTTP param → helper method
        String result = findUserSafely(username);

        resp.getWriter().println(result);
    }

    private String findUserSafely(String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");

        // SANITIZER: parameterized query — input is never concatenated
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();

        return rs.next() ? rs.getString("email") : "not found";
    }
}
