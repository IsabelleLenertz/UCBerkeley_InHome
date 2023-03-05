package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;
import UCB.MICS.InHome.jdbc.JdbcClient;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
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
            client.updatePolicy(nameFrom, nameTo);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, String.format("could not add new policy %s", e.getMessage()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        logger.log(Level.INFO, String.format("new device was added mac=%s, ip=%s", nameFrom, nameTo));
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
                        .put("deviceTo", policy.get("deviceTo"))
                        .put("deviceFrom", policy.get("deviceFrom"));
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
            List<Map<String, String>> policies = null;
            try {
                policies = client.getAllPoliciesFromName(name);
            } catch (SQLException e) {
                logger.log(Level.SEVERE, String.format("could get policies %s", e.getMessage()));
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
            if(policies == null || policies.isEmpty()) {
                logger.log(Level.INFO, String.format("device not found, name=%s", name));
                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Device not found");
                return;
            }
            // Return a json array with MAC, IpV4, device name
            JSONArray json = new JSONArray();
            for (Map<String, String> policy : policies) {
                JSONObject jsonDevice = new JSONObject().put("policyId", policy.get("policyId"))
                        .put("deviceTo", policy.get("deviceTo"))
                        .put("deviceFrom", policy.get("deviceFrom"));
                json.put(jsonDevice);
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType(APPLICATION_JSON);
            resp.getWriter().write(json.toString());
            resp.getWriter().flush();
            logger.log(Level.INFO, String.format("all policies were returned from name=%s", name));

        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }


}
