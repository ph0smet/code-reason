import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.Statement;

public class OrderService extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String id = req.getParameter("id");
        String result = processOrder(id);
        sendResponse(resp, result);
    }

    private String processOrder(String orderId) {
        String validated = validate(orderId);
        return executeQuery(validated);
    }

    private String validate(String input) {
        return input.trim();
    }

    private String executeQuery(String param) {
        try {
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM orders WHERE id = '" + param + "'");
            return "found";
        } catch (Exception e) {
            return "error";
        }
    }

    private void sendResponse(HttpServletResponse resp, String data) {
        // write response
    }
}
