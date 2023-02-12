package UCB.MICS.InHome;

import com.google.common.io.Resources;
import com.google.inject.servlet.GuiceFilter;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.servlet.DispatcherType;
import java.util.EnumSet;


public final class Main
{
    public Main()
    {
    }

    public static void main(String[] args) throws Exception {
        Server svr = new Server();
        // Guice-powered servlet
        ServletContextHandler handler = new ServletContextHandler();

        handler.setResourceBase(".");

        // Register Guice Filter
        handler.addFilter( GuiceFilter.class, "/*", EnumSet.allOf(DispatcherType.class));
        // add a lifecycle listener to bootstrap injector on startup
        handler.addEventListener(new EventListener());


        svr.setHandler(handler);

        /**
         * Credit for setting up https: https://www.eclipse.org/jetty/documentation/jetty-10/programming-guide/index.html#pg-server
         */
        HttpConfiguration httpConfig = new HttpConfiguration();
        // Add the secureRequestCustomizer because we are using TLS
        httpConfig.addCustomizer(new SecureRequestCustomizer());

        // The connectionFactory for HTTP/1.1
        HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

        // Configure the sslContextFactory with keystore information
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        String path = Resources.getResource("keystore").getPath();
        path = path.startsWith("/")? path.substring(1):path;
        sslContextFactory.setKeyStorePath("src/main/resources/keystore");
        sslContextFactory.setKeyStorePassword("123456");

        // The connectionFactory for TLS
        SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

        // The ServerConnector instance
        ServerConnector connector = new ServerConnector(svr, tls, http11);
        connector.setPort(8443);
        svr.addConnector(connector);

        svr.start();
        svr.join();
    }
}
