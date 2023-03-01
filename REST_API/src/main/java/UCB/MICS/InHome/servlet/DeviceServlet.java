package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;
import UCB.MICS.InHome.jdbc.JdbcClient;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static UCB.MICS.InHome.Utilities.*;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

@Singleton
public class DeviceServlet extends HttpServlet {

    private final Logger logger = Logger.getLogger("AdminServlet");
    private final JdbcClient client;
    @Inject
    public DeviceServlet(JdbcClient client) {
        this.client = checkNotNull(client, "JDBC client cannot be null");
    }
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException
    {
        HttpSession session = req.getSession(false);
        Map<String, String> json = null;
        try {
            json = Utilities.getFromRequest(req);
        } catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed json");
            return;
        }
        String mac = json.get(MAC);
        String name = json.get(NAME);
        String ip = json.get(IPV4);
        if (isNullOrEmpty(mac)||isNullOrEmpty(name)||isNullOrEmpty(ip)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name, mac, or ip missing");
            return;
        }
        if (name.length() > 30) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name cannot be more than 30 characters");
            return;
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
            client.addDevice(name, macB, ipB);
        } catch (SQLException e) {
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
            return;
        }
        String mac = json.get("mac");
        if (isNullOrEmpty(mac)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "mac missing");
            return;
        }
        byte[] macB = null;
        try {
            macB = Utilities.macToByteArray(mac);
        }
        catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "MAC address malformed");
            return;
        }

        // Do the following as a single transaction
        // Delete MAC from DB
        try {
            client.removeDevice(macB);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could not delete device mac %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("a device was deleted, mac:%s", mac));
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
            return;
        }
        String oldName = json.get(OLD_NAME);
        String newName = json.get(NEW_NAME);
        if (oldName.length() > 30 || newName.length() > 30) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name cannot be more than 30 characters");
            return;
        }
        if(isNullOrEmpty(oldName) || isNullOrEmpty(newName)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "old or new name is missing");
            return;
        }
        try {
            client.updateName(newName, oldName);
        }
        catch(SQLException e) {
            logger.log(Level.SEVERE, String.format("could not update device name %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("name of a device was changed old:%s, new:%s", oldName, newName));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String path = req.getServletPath();
        String[] pathElements = path.split("/");
        // if no path param is specified, get all the devices
        if (pathElements.length == 3){
            getAllDevices(resp);
        }
        else if (pathElements.length == 4) {
            getOne(pathElements[3].replace('-', ':'), resp);
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
    private void getAllDevices(HttpServletResponse resp) throws IOException {
        List<Map<String, String>> devices = null;
        try {
            devices = client.getAllDevices();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could get devices %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        // Return a json array with MAC, IpV4, device name
        JSONArray json = new JSONArray();
        for (Map<String, String> device : devices) {
            JSONObject jsonDevice = new JSONObject().put(MAC, device.get(MAC))
                    .put(IPV4, device.get(IPV4))
                    .put(IPV6, device.get(IPV6))
                    .put(NAME, device.get(NAME))
                    .put(DATE_ADDED, device.get(DATE_ADDED))
                    .put(IS_TRUSTED, device.get(IS_TRUSTED));
            json.put(jsonDevice);
        }
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(APPLICATION_JSON);
        resp.getWriter().write(json.toString());
        resp.getWriter().flush();
        logger.log(Level.INFO, "all devices were returned");
    }

    private void getOne(String mac, HttpServletResponse resp) throws IOException {
        Map<String, String> json = null;
        byte[] macB = null;
        try {
            macB = Utilities.macToByteArray(mac);
        }
        catch(NumberFormatException e){
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "MAC address malformed");
            return;
        }
        Map<String, String> device = Map.of();
        try {
            device = client.getOneDevice(macB);
        }
        catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could get device %s", e.getMessage()));
        }
        if(device == null || device.isEmpty()) {
            logger.log(Level.INFO, String.format("device not found, mac=%s", mac));
            resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Device not found");
            return;
        }
        JSONObject jsonDevice = new JSONObject().put(MAC, device.get(MAC))
                    .put(IPV4, device.get(IPV4))
                    .put(IPV6, device.get(IPV6))
                    .put(NAME, device.get(NAME))
                    .put(DATE_ADDED, device.get(DATE_ADDED))
                    .put(IS_TRUSTED, device.get(IS_TRUSTED));
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType(APPLICATION_JSON);
        resp.getWriter().write(jsonDevice.toString());
        resp.getWriter().flush();
        logger.log(Level.INFO, "one device was returned");
    }
}
