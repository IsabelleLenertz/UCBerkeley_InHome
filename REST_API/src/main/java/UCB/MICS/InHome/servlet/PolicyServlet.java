package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
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
            throws IOException {
        String path = req.getServletPath();
        String[] elements = path.split("/");
        if (elements.length == 3 && elements[2].equals("get")) {
            // Retrieve all the policies
        }
        else if (elements.length == 4 && elements[2].equals("get")) {
            String id = elements[2];
            // Retrieve policy with the given id
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
    {

        logger.log(Level.INFO, "policy management put was called");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String path = req.getServletPath();
        String[] elements = path.split("/");
        if (elements.length == 3 && elements[2].equals("delete")) {
            // delete all the policies
        }
        else if (elements.length == 4 && elements[2].equals("delete")) {
            String mac = elements[2];
            boolean result = deletePolicyByDeviceMac(Utilities.macToByteArray(mac));
            resp.setStatus(200);
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
        logger.log(Level.INFO, "policy management delete was called");
    }

    protected boolean deletePolicyByDeviceMac(byte[] macB)
    {
        // Delete all the policy mentioning the given device
        return false;
    }
}
