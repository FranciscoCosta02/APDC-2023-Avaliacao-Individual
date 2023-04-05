package pt.unl.fct.di.apdc.aval.resources;

import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.aval.utils.LoginData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;

@Path("/delete")
public class DeleteResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    public DeleteResource() {
    }

    @DELETE
    @Path("/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response deleteUser(LoginData user, @PathParam("username") String username) {
        LOG.fine("Attempt to delete user: " + username);
        Transaction txn = datastore.newTransaction();
        try{
            Key userKey = userKeyFactory.newKey(user.username);
            Key delKey = userKeyFactory.newKey(username);
            Entity user2 = txn.get(userKey);
            Entity del = txn.get(delKey);
            if(user2 == null || del == null){
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            String confirmation = user2.getString("password");
            if(!confirmation.equals(DigestUtils.sha512Hex(user.password)))
                return Response.status(Status.NOT_ACCEPTABLE).entity("Error: Wrong password").build();

            switch (user2.getString("role")){
                case "User":
                    if(!user.username.equals(username))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    txn.delete(delKey);
                    txn.commit();
                    LOG.fine("User deleted: " + username);
                    return Response.ok().build();
                case "GBO":
                    if(del.getString("role").equals("User")) {
                        txn.delete(delKey);
                        txn.commit();
                        LOG.fine("User deleted: " + username);
                        return Response.ok().build();
                    } else {
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    }
                case "GS":
                    String delRole = del.getString("role");
                    if(delRole.equals("User") || delRole.equals("GBO")) {
                        txn.delete(delKey);
                        txn.commit();
                        LOG.fine("User deleted: " + username);
                        return Response.ok().build();
                    } else {
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    }
                case "SU":
                    txn.delete(delKey);
                    txn.commit();
                    LOG.fine("User deleted: " + username);
                    return Response.ok().build();
            }
            return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();

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
