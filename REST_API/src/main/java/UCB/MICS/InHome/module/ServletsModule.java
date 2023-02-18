package UCB.MICS.InHome.module;

import UCB.MICS.InHome.jdbc.JdbcClient;
import UCB.MICS.InHome.servlet.DeviceServlet;
import UCB.MICS.InHome.servlet.LoginServlet;
import UCB.MICS.InHome.servlet.PolicyServlet;
import com.google.inject.Scopes;
import com.google.inject.servlet.ServletModule;

public class ServletsModule extends ServletModule {

    @Override
    protected void configureServlets() {
        bind(JdbcClient.class);
        bind(DeviceServlet.class).in(Scopes.SINGLETON);
        serve("/v1/device-management", "/v1/device-management/" ).with(DeviceServlet.class);

        bind(PolicyServlet.class).in(Scopes.SINGLETON);
        serveRegex("/v1/policy-management/?", "/v1/policy-management/get/?[0-9]{0,5}",
                "/v1/policy-management/delete/?[0-9]{0,5}").with(PolicyServlet.class);

        bind(LoginServlet.class).in(Scopes.SINGLETON);
        serve("/v1/login").with(LoginServlet.class);
    }
}
