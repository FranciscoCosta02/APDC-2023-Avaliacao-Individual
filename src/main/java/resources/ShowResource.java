package resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

@Path("/show")
public class ShowResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
    private final Gson g = new Gson();
    public ShowResource() {
    }

    @GET
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showToken(@Context HttpServletRequest request) {
        String id = request.getHeader("Authorization");
        id = id.substring("Bearer".length()).trim();
        Transaction txn = datastore.newTransaction();
        try{
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Response.Status.BAD_REQUEST).entity("Token does not exist.").build();
            }
            return Response.ok(g.toJson(token)).build();
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
