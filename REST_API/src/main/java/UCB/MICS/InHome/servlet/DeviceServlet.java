package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;
import UCB.MICS.InHome.jdbc.JdbcClient;

import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.common.base.Strings.isNullOrEmpty;

@Singleton
public class DeviceServlet extends HttpServlet {

    Logger logger = Logger.getLogger("AdminServlet");
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException
    {
        Map<String, String> json = null;
        try {
            json = Utilities.getFromRequest(req);
        } catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed json");
            return;
        }
        String mac = json.get("mac");
        String name = json.get("name");
        String ip = json.get("ip");
        if (isNullOrEmpty(mac)||isNullOrEmpty(name)||isNullOrEmpty(ip)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name, mac, or ip missing");
        }
        byte[] ipB = null;
        try {
            ipB = Utilities.ipV4ToByteArray(ip);
        }
        catch (NumberFormatException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "IP malformed");
            return;
        }
        byte[] macB = null;
        try {
            macB = Utilities.macToByteArray(mac);
        }
        catch(NumberFormatException e){
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "MAC address malformed");
            return;
        }

        try {
            JdbcClient client = new JdbcClient();
            client.addDevice(name, macB, ipB);
        } catch (SQLException | ClassNotFoundException e) {
            logger.log(Level.SEVERE, String.format("could not add new device %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("new device was added mac=%s, ip=%s", mac, ip));
        resp.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        Map<String, String> json = null;
        try {
            json = Utilities.getFromRequest(req);
        }
        catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed json");
        }
        String mac = json.get("mac");
        if (isNullOrEmpty(mac)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "mac missing");
        }
        byte[] macB = null;
        try {
            macB = Utilities.macToByteArray(mac);
        }
        catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "MAC address malformed");
        }

        // Do the following as a single transaction
        // Delete MAC from DB
        JdbcClient client = null;
        try {
            client = new JdbcClient();
            client.removeDevice(macB);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        // Delete related policies

        // Update DB revisions table

        logger.log(Level.INFO, "delete was called");
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        Map<String, String> json = null;
        try {
            json = Utilities.getFromRequest(req);
        }
        catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed json");
        }
        String oldName = json.get("old");
        String newName = json.get("new");
        if(isNullOrEmpty(oldName) || isNullOrEmpty(newName)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "old or new name is missing");
        }

        logger.log(Level.INFO, "put was called");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            JdbcClient client = new JdbcClient();
            List<String> devices = client.getDeviceNames();
            for(var element: devices) {
                logger.log(Level.INFO, element);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        // Query DB to get all the devices

        // Return a json array with MAC, IpV4, device name

        logger.log(Level.INFO, "get was called");
    }
}
