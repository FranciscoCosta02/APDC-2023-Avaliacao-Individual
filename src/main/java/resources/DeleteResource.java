package resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;

@Path("/delete")
public class DeleteResource {
    private static final Logger LOG = Logger.getLogger(DeleteResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
    private final Gson g = new Gson();
    public DeleteResource() {
    }

    @DELETE
    @Path("/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response deleteUser(@Context HttpServletRequest request, @PathParam("username") String username) {
        String id = request.getHeader("Authorization");
        LOG.fine("Attempt to delete user: " + username);
        Transaction txn = datastore.newTransaction();
        try{
            id = id.substring("Bearer".length()).trim();
            Key tokenKey = tokenKeyFactory.newKey(id);
            Key delKey = datastore.newKeyFactory().setKind("User").newKey(username);
            Entity token = txn.get(tokenKey);
            Entity del = txn.get(delKey);
            if(token == null || del == null){
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            String delRole = del.getString("role");
            switch (token.getString("role")){
                case "User":
                    if(!token.getString("username").equals(username))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "GBO":
                    if(!delRole.equals("User"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "GS":
                    if(!delRole.equals("User") && !delRole.equals("GBO"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "SU":
                    break;
                default:
                    return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
            }
            txn.delete(delKey);
            txn.commit();
            LOG.fine("User deleted: " + username);
            return Response.ok().build();
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Status.FORBIDDEN).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

}
