package UCB.MICS.InHome;

import UCB.MICS.InHome.resources.AdminResource;
import com.google.inject.Binder;
import com.google.inject.Module;

import static com.proofpoint.jaxrs.JaxrsBinder.jaxrsBinder;

public class MainModule
        implements Module
{
    @Override
    public void configure(Binder binder)
    {
        binder.requireExplicitBindings();
        binder.disableCircularProxies();
        jaxrsBinder(binder).bind(AdminResource.class).withApplicationPrefix();
    }
}
