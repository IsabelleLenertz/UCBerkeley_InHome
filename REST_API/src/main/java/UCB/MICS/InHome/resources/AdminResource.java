package UCB.MICS.InHome.resources;

import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("v1/device-management")
public class AdminResource {

    @POST
    public Response addDevice()
    {
        return null;
    }

    @DELETE
    public Response removeDevice()
    {
       return null;
    }

    @PUT
    public Response changeName()
    {
        return null;
    }
}

