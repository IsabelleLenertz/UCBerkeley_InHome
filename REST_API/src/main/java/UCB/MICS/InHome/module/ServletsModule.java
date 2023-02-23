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
        serveRegex("/v1/device-management/?[0-9a-zA-Z\\.]{0,20}").with(DeviceServlet.class);

        bind(PolicyServlet.class).in(Scopes.SINGLETON);
        serveRegex("/v1/policy-management/?[0-9]{0,5}").with(PolicyServlet.class);
        bind(LoginServlet.class).in(Scopes.SINGLETON);
        serveRegex("/v1/login/?(newuser)?").with(LoginServlet.class);
        filter("/*").through(CorsFilter.class);
    }
}
