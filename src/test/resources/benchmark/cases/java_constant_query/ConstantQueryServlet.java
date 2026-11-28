package benchmark.constantquery;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;

public class ConstantQueryServlet extends HttpServlet {
    public void handle(HttpServletRequest request, Statement statement) throws Exception {
        String unused = request.getParameter("name");
        statement.executeQuery("SELECT name FROM users WHERE active = 1");
        System.out.println(unused);
    }
}
