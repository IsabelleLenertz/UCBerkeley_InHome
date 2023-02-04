package UCB.MICS.InHome.module;

import UCB.MICS.InHome.servlet.AdminServlet;
import com.google.inject.servlet.ServletModule;

public class AdminServletModule  extends ServletModule {

    @Override
    protected void configureServlets() {
        bind(AdminServlet.class);
        serve("/v1/device-management").with(AdminServlet.class);
    }
}
