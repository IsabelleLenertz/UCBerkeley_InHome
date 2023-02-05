package UCB.MICS.InHome;

import com.google.inject.servlet.GuiceFilter;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;

import javax.servlet.DispatcherType;
import java.util.EnumSet;


public final class Main
{
    private Main()
    {
    }

    public static void main(String[] args) throws Exception {
        Server svr = new Server(8443);

        // Guice-powered servlet
        ServletContextHandler handler = new ServletContextHandler();
        handler.setResourceBase(".");

        // Register Guice Filter
        handler.addFilter( GuiceFilter.class, "/*", EnumSet.allOf(DispatcherType.class));
        // add a lifecycle listener to bootstrap injector on startup
        handler.addEventListener(new EventListener());


        svr.setHandler(handler);


        svr.start();
        svr.join();
    }
}
