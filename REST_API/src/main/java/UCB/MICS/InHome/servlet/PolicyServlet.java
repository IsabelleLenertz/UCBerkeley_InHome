package UCB.MICS.InHome.servlet;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PolicyServlet extends HttpServlet {
    Logger logger = Logger.getLogger("PolicyServlet");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "device management post was called");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "device management get was called");
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "device management put was called");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "device management delete was called");
    }
}
