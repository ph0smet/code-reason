package fixtures.tier1.sqli;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.PrintWriter;

/**
 * Tier 1 fixture: single-file, single-method SQLi.
 * Source and sink are in the same method — no function boundary crossing.
 * Label: vulnerable, single-method SQL injection.
 */
public class SearchServlet extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String query = req.getParameter("query");  // SOURCE: user-controlled input

        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
        Statement stmt = conn.createStatement();

        // SINK: user input concatenated directly into SQL string
        ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE name = '" + query + "'");

        PrintWriter out = resp.getWriter();
        while (rs.next()) {
            out.println(rs.getString("name"));
        }
    }
}
