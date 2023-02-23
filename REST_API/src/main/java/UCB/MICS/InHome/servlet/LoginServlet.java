package UCB.MICS.InHome.servlet;

import com.mysql.cj.util.Base64Decoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.eclipse.jetty.util.security.Credential.MD5.digest;

public class LoginServlet extends HttpServlet {
    Logger logger = Logger.getLogger("LoginServlet");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        String[] pathElements = path.split("/");
        String username;
        String password = "";
        String authorization = req.getHeader("authorization");
        if(authorization.toLowerCase().startsWith("basic")) {
            String[] credentials = new String(Base64.getDecoder().decode(authorization.substring(6).trim()),
                    StandardCharsets.UTF_8).split(":");
            if (credentials.length == 2) {
                username = credentials[0];
                password = credentials[1];
            }
        }
        // Login existing user
        if (pathElements.length ==3){
                // TODO: check is length of username <= 30
                Security.addProvider(new BouncyCastleProvider());
                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
                    byte[] hash = messageDigest.digest(password.getBytes());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
        }

        //Create New user
        else {

        }

        logger.log(Level.INFO, "login post was called");
    }

    /**
     * // register the BouncyCastleProvider with the Security Manager
     * Security.addProvider(new BouncyCastleProvider());
     *
     * String plainString = "Plaintext Secret";
     *
     * MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
     * byte[] hashedString = messageDigest.digest(plainString.getBytes());
     *
     * doSomething().with(hashedString);
     * @param req
     * @param resp
     */
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
