package fixtures.tier3.sqli;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tier 3 fixture: cross-file SQLi via Controller → Service → DAO.
 * Source enters here; no SQL in this file at all.
 * Without taint tracking across files, the vulnerability is invisible from this file alone.
 */
public class OrderController extends HttpServlet {

    private final OrderService orderService = new OrderService();

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String orderId = req.getParameter("id");  // SOURCE: HTTP query param

        // Passes user input to service layer — no obvious danger visible here
        String result = orderService.getOrderDetails(orderId);

        resp.getWriter().println(result);
    }
}
