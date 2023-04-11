package resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LogoutResource {

    private static final Logger LOG = Logger.getLogger(LogoutResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService ();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
    private final Gson g = new Gson();

    @DELETE
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response logout(@Context HttpServletRequest request) {
        String id = request.getHeader("Authorization");
        id = id.substring("Bearer".length()).trim();
        Key tokenKey = tokenKeyFactory.newKey(id);
        Transaction txn = datastore.newTransaction();
        try {
            Entity token = txn.get(tokenKey);
            if (token == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            String username = token.getString("username");
            txn.delete(tokenKey);
            txn.commit();
            LOG.fine("User logged out: " + username);
            return Response.ok(g.toJson(username)).build();
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Response.Status.FORBIDDEN).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
