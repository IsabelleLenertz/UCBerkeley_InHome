package UCB.MICS.InHome;

import UCB.MICS.InHome.module.AdminServletModule;
import com.google.inject.Guice;
import com.google.inject.servlet.GuiceFilter;
import com.proofpoint.log.Logger;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.component.LifeCycle;

import javax.servlet.DispatcherType;
import java.util.EnumSet;

import static com.proofpoint.bootstrap.Bootstrap.bootstrapApplication;

public final class Main
{
    private static final Logger log = Logger.get(Main.class);

    private Main()
    {
    }

    public static void main(String[] args) throws Exception {
        Server svr = new Server(8443);

        // Guice-powered servlet
        ServletContextHandler handler = new ServletContextHandler();
        handler.setResourceBase(".");

        // Register Guice Filter
        handler.addFilter(GuiceFilter.class, "/*", EnumSet.allOf(DispatcherType.class));
        svr.setHandler(handler);

        // add a lifecycle listener to bootstrap injector on startup
        svr.addLifeCycleListener(new AbstractLifeCycle.AbstractLifeCycleListener() {
            @Override
            public void lifeCycleStarted(LifeCycle event) {
                System.out.println("Bootstrapping Guice injector ...");
                Guice.createInjector(new AdminServletModule());
            }
        });

        svr.start();
        svr.join();
    }
}
