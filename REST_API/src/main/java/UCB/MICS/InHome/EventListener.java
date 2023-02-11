package UCB.MICS.InHome;

import UCB.MICS.InHome.module.ServletsModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceServletContextListener;

import java.util.logging.Level;
import java.util.logging.Logger;

public class EventListener extends GuiceServletContextListener {
    Logger logger = Logger.getLogger("context listener");

    @Override
    protected Injector getInjector() {
        logger.log(Level.INFO, "listener started");
        return Guice.createInjector(new ServletsModule());
    }
}
