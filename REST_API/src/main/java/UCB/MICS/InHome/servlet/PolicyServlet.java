package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.Utilities;
import UCB.MICS.InHome.jdbc.JdbcClient;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
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
        }
        else if (elements.length == 4) {
            String id = elements[3];
            // Retrieve policy with the given id
        }
        else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }


}
