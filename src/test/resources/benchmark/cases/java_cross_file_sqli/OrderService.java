package fixtures.tier3.sqli;

/**
 * Service layer — passes the order ID through without modification.
 * No SQL here either. The taint just propagates.
 */
public class OrderService {

    private final OrderDao orderDao = new OrderDao();

    public String getOrderDetails(String orderId) throws Exception {
        // No transformation, no sanitization — tainted value passes straight through
        return orderDao.fetchOrder(orderId);
    }
}
