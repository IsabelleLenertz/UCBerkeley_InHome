package UCB.MICS.InHome.servlet;

import UCB.MICS.InHome.ForLoginCookieMap;
import UCB.MICS.InHome.jdbc.JdbcClient;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.SessionIdManager;

import javax.inject.Inject;
import javax.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.fasterxml.jackson.databind.type.LogicalType.DateTime;
import static com.google.common.base.Preconditions.checkNotNull;

public class LoginServlet extends HttpServlet {
    Logger logger = Logger.getLogger("LoginServlet");

    private final JdbcClient client;
    private final ConcurrentHashMap cookies;

    @Inject
    public LoginServlet(JdbcClient client, @ForLoginCookieMap ConcurrentHashMap<String, String> cookies) {
        this.client = checkNotNull(client, "JDBC client cannot be null");
        this.cookies = checkNotNull(cookies, "Cookies map cannot not be null");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = "";
        String password = "";
        String authorization = req.getHeader("authorization");
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA3-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        if(authorization.toLowerCase().startsWith("basic")) {
            String[] credentials = new String(Base64.getDecoder().decode(authorization.substring(6).trim()),
                    StandardCharsets.UTF_8).split(":");
            if (credentials.length == 2) {
                username = credentials[0];
                password = credentials[1];
            } else {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        } else {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "auth header missing");
        }
        //Create New user
        String salt = RandomStringUtils.randomAlphanumeric(5);
        byte[] hash = messageDigest.digest((password + salt).getBytes());
        if (client.insertUser(username, salt, hash)) { // returns false is the user already exists
            resp.setStatus(HttpServletResponse.SC_OK);
            logger.log(Level.INFO, String.format("new user was created: %s", username));
        }
        else {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "user already exists");
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = "";
        String password = "";
        String authorization = req.getHeader("authorization");
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA3-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        if(authorization.toLowerCase().startsWith("basic")) {
            String[] credentials = new String(Base64.getDecoder().decode(authorization.substring(6).trim()),
                    StandardCharsets.UTF_8).split(":");
            if (credentials.length == 2) {
                username = credentials[0];
                password = credentials[1];
            } else {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        } else {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "auth header missing");
        }

        if (client.loginUser(username, password))  {
            //setting cookie to expire in 30 mins
            Cookie loginCookie = new Cookie(username, "randomUUID");
            loginCookie.setMaxAge(15*60);
            cookies.put(username, "randomUUID");
            resp.addCookie(loginCookie);
            resp.setStatus(HttpServletResponse.SC_OK);
        }
        else {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
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
