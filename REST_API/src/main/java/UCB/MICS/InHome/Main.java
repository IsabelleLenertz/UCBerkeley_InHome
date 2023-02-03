package UCB.MICS.InHome;

import com.google.common.collect.ImmutableMap;
import com.google.inject.Injector;
import com.proofpoint.audit.AuditLogModule;
import com.proofpoint.discovery.client.DiscoveryModule;
import com.proofpoint.discovery.client.announce.Announcer;
import com.proofpoint.http.server.HttpServerModule;
import com.proofpoint.jaxrs.JaxrsModule;
import com.proofpoint.jmx.JmxHttpModule;
import com.proofpoint.jmx.JmxModule;
import com.proofpoint.json.JsonModule;
import com.proofpoint.log.LogJmxModule;
import com.proofpoint.log.Logger;
import com.proofpoint.node.NodeModule;
import com.proofpoint.reporting.ReportingClientModule;
import com.proofpoint.reporting.ReportingModule;
import org.weakref.jmx.guice.MBeanModule;

import static com.proofpoint.bootstrap.Bootstrap.bootstrapApplication;

public final class Main
{
    private static final Logger log = Logger.get(Main.class);

    private Main()
    {
    }

    public static void main(String[] args)
    {
        try {
            Injector injector = bootstrapApplication("skeleton")
                    .withModules(
                            new NodeModule(),
                            new DiscoveryModule(),
                            new HttpServerModule(),
                            new JsonModule(),
                            new JaxrsModule(),
                            new MBeanModule(),
                            new JmxModule(),
                            new JmxHttpModule(),
                            new LogJmxModule(),
                            new AuditLogModule(),
                            new ReportingModule(),
                            new ReportingClientModule(),
                            new MainModule()

                    )
                    .withApplicationDefaults(ImmutableMap.<String, String>builder()
                            .put("http-server.http.enabled", "false")
                            .put("http-server.https.enabled", "true")
                            .put("http-server.https.port", "8443")
                            .build()
                    )
                    .initialize();

            injector.getInstance(Announcer.class).start();
        }
        catch (Throwable e) {
            log.error(e);
            System.exit(1);
        }
    }
}
