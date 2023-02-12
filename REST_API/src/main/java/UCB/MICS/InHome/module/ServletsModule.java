package UCB.MICS.InHome.module;

import UCB.MICS.InHome.servlet.DeviceServlet;
import UCB.MICS.InHome.servlet.LoginServlet;
import UCB.MICS.InHome.servlet.PolicyServlet;
import com.google.inject.Scopes;
import com.google.inject.servlet.ServletModule;

public class ServletsModule extends ServletModule {

    @Override
    protected void configureServlets() {
        bind(DeviceServlet.class).in(Scopes.SINGLETON);
        serve("/v1/device-management").with(DeviceServlet.class);

        bind(PolicyServlet.class).in(Scopes.SINGLETON);
        serve("/v1/policy-management").with(PolicyServlet.class);

        bind(LoginServlet.class).in(Scopes.SINGLETON);
        serve("/v1/login").with(LoginServlet.class);
    }
}
