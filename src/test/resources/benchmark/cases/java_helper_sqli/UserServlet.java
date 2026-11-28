package fixtures.tier2.sqli;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.PrintWriter;

/**
 * Tier 2 fixture: cross-function SQLi within a single file.
 * Source is in doGet(); tainted value flows into findUserByName() via method call.
 * Label: vulnerable SQL injection through a helper method.
 */
public class UserServlet extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String username = req.getParameter("user");  // SOURCE: HTTP query param

        // Tainted value passed to a helper — requires interprocedural reasoning
        String result = findUserByName(username);

        resp.getWriter().println(result);
    }

    private String findUserByName(String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
        Statement stmt = conn.createStatement();

        // SINK: tainted parameter arrives here through the call chain
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + name + "'");

        return rs.next() ? rs.getString("email") : "not found";
    }
}
