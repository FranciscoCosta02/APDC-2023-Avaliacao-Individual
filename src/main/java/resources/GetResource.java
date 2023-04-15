package resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

        @Path("/get")
        public class GetResource {
            private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
            private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
            private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
            private final Gson g = new Gson();

            public GetResource() {
    }

    @GET
    @Path("/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam("username") String username) {
        Transaction txn = datastore.newTransaction();
        try {
            Entity user = datastore.get(userKeyFactory.newKey(username));
            return Response.ok(g.toJson(user)).build();
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