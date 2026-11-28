package fixtures.tier3.sqli;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * DAO layer — this is where the SQL lives.
 * Receives the order ID that originated as an HTTP parameter two hops away.
 * Reading this file alone looks fine — orderId appears to be just a String parameter.
 * Reading OrderController alone looks fine — it just calls a service.
 * Only cross-file taint analysis connects the source to this sink.
 */
public class OrderDao {

    public String fetchOrder(String orderId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
        Statement stmt = conn.createStatement();

        // SINK: orderId originated from req.getParameter() in OrderController, two files away
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'");

        return rs.next() ? rs.getString("status") : "not found";
    }
}
