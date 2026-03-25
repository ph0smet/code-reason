import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SampleController extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String id = req.getParameter("id");
        // handle GET request
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String body = req.getParameter("data");
        // handle POST request
    }

    private void helperMethod(String data) {
        // not an entry point
    }

    public static void main(String[] args) {
        // CLI entry point
    }
}
