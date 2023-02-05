package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.JsonUtilities;

import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.common.base.Strings.isNullOrEmpty;

@Singleton
public class AdminServlet extends HttpServlet {

    Logger logger = Logger.getLogger("AdminServlet");
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        Map<String, String> json = JsonUtilities.getFromRequest(req);
        String mac = json.get("mac");
        String name = json.get("name");
        String ip = json.get("ip");
        if(isNullOrEmpty(mac)||isNullOrEmpty(name)||isNullOrEmpty(ip)){
            // return error request malformed
        }
        Long longMac = Long.parseLong(mac, 16);
        byte[] ipB = JsonUtilities.ipToByteArray(ip);

        logger.log(Level.INFO, "post was called");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        logger.log(Level.INFO, "delete was called");
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        logger.log(Level.INFO, "put was called");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        logger.log(Level.INFO, "get was called");
    }
}
