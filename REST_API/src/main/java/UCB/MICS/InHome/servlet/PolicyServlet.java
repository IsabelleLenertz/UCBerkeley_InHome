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
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static UCB.MICS.InHome.Utilities.*;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

@Singleton
public class PolicyServlet extends HttpServlet {
    private final Logger logger = Logger.getLogger("AdminServlet");
    private final JdbcClient client;
    @Inject
    public PolicyServlet(JdbcClient client) {
        this.client = checkNotNull(client, "JDBC client cannot be null");
    }
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException
    {
        Map<String, String> json = null;
        try {
            json = Utilities.getFromRequest(req);
        } catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "malformed json");
            return;
        }
        String nameFrom = json.get("namedevicefrom");
        String nameTo = json.get("namedeviceto");

        if (isNullOrEmpty(nameFrom)||isNullOrEmpty(nameTo)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name of device from or to missing");
            return;
        }
        if (nameFrom.length() > 30 || nameTo.length() > 30) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "name of from or to device cannot be more than 30 characters");
            return;
        }

        try {
            if(!client.updatePolicy(nameFrom, nameTo)) {
                logger.log(Level.INFO, String.format("device not found, could not add policy"));
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could not add new policy %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("new policy was added device 1=%s, device 2=%s", nameFrom, nameTo));
        resp.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        String[] elements = path.split("/");
        if (elements.length == 3) {
            // Retrieve all the policies
            List<Map<String, String>> policies = null;
            try {
                policies = client.getAllPolicies();
            } catch (SQLException e) {
                logger.log(Level.SEVERE, String.format("could get policies %s", e.getMessage()));
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
            // Return a json array with MAC, IpV4, device name
            JSONArray json = new JSONArray();
            for (Map<String, String> policy : policies) {
                JSONObject jsonDevice = new JSONObject().put("policyId", policy.get("policyId"))
                        .put("device_1", policy.get("deviceTo"))
                        .put("device_2", policy.get("deviceFrom"));
                json.put(jsonDevice);
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType(APPLICATION_JSON);
            resp.getWriter().write(json.toString());
            resp.getWriter().flush();
            logger.log(Level.INFO, "all policies were returned");
        }
        else if (elements.length == 4) {
            String name = elements[3];
            // Retrieve policy with the given device name
            List<Map<String, String>> devices;
            try {
                devices = client.getAllPoliciesFromName(name);
            } catch (SQLException e) {
                logger.log(Level.SEVERE, String.format("could not get policies %s", e.getMessage()));
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
            if(devices == null || devices.isEmpty()) {
                logger.log(Level.INFO, String.format("device not found, name=%s", name));
                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Device not found");
                return;
            }
            // Return a json array with MAC, IpV4, device name
            JSONArray array = new JSONArray();
            for(var device : devices) {
               array.put( new JSONObject()
                       .put(NAME, device.get(NAME))
                       .put(MAC, device.get(MAC))
                       .put(IPV4, device.get(IPV4)));
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType(APPLICATION_JSON);
            resp.getWriter().write(array.toString());
            resp.getWriter().flush();
            logger.log(Level.INFO, String.format("all policies were returned from name=%s", name));
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
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
        String policyId = json.get("policyId");
        if (isNullOrEmpty(policyId)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "policyId missing");
            return;
        }

        try {
            client.removeByPolicyId(Integer.parseInt(policyId));
        } catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could not delete policyId %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("a device was deleted, PolicyId:%s", policyId));
    }

}
