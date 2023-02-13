package UCB.MICS.InHome.servlet;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoginServlet extends HttpServlet {
    Logger logger = Logger.getLogger("LoginServlet");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "login post was called");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "login get was called");
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "login put was called");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
    {
        logger.log(Level.INFO, "login delete was called");
    }
}
