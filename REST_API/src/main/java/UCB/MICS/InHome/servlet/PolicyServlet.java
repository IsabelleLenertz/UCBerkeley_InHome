package UCB.MICS.InHome.servlet;

import javax.inject.Singleton;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Singleton
public class PolicyServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
    {

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        String[] elements = path.split("/");
        if (elements.length == 3) {
            // Retrieve all the policies
        }
        else if (elements.length == 4) {
            String id = elements[3];
            // Retrieve policy with the given id
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }


}
