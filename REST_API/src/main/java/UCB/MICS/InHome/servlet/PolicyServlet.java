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
        logger.log(Level.INFO, "policy management post was called");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        System.out.println("context path: " + req.getContextPath());
        System.out.println("servlet path: " + req.getServletPath());
        System.out.println("path info: " + req.getPathInfo());
        System.out.println("path param: " + req.getQueryString().split("&")[0].split("=")[1]);
        logger.log(Level.INFO, "policy management get was called");
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "policy management put was called");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "policy management delete was called");
    }
}
