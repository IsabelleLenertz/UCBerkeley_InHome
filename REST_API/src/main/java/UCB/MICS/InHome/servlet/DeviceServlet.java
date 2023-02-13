package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;

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
        }
        String mac = json.get("mac");
        String name = json.get("name");
        String ip = json.get("ip");
        if (isNullOrEmpty(mac)||isNullOrEmpty(name)||isNullOrEmpty(ip)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name, mac, or ip missing");
        }
        try {
            byte[] ipB = Utilities.ipV4ToByteArray(ip);
        }
        catch (NumberFormatException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "IP malformed");
        }
        byte[] macB = null;
        try {
            macB = Utilities.macToByteArray(mac);
        }
        catch(NumberFormatException e){
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "MAC address malformed");
        }

        // Dot the following as a single transaction
        // Save info to database

        // Update database revision


        logger.log(Level.INFO, String.format("new device was added mac=%s, ip=%s", mac, ip));
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
        String mac = json.get("MAC");
        if (isNullOrEmpty(mac)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name, mac, or ip missing");
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
            throws ServletException, IOException
    {
        // Query DB to get all the devices

        // Return a json array with MAC, IpV4, device name

        logger.log(Level.INFO, "get was called");
    }
}
