package resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import utils.AuthToken;
import utils.LoginData;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();
    public LoginResource() {
    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(LoginData user,
                          @Context HttpServletRequest request,
                          @Context HttpHeaders headers) {
        LOG.fine("Attempt to login user: " + user.username);
        Key userKey = userKeyFactory.newKey(user.username);
        Transaction txn = datastore.newTransaction();
        try{
            Entity user2 = txn.get(userKey);
            if(user2 == null){
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            String confirmation = user2.getString("password");
            if(confirmation.equals(DigestUtils.sha512Hex(user.password))) {
                String role = user2.getString("role");
                AuthToken at = new AuthToken(user.username, role);
                Key authKey = datastore.newKeyFactory().setKind("Token").newKey(at.tokenID);
                Entity auth = txn.get(authKey);
                while(auth != null) {
                    at = new AuthToken(user.username, role);
                    authKey = datastore.newKeyFactory().setKind("Token").newKey(at.tokenID);
                    auth = txn.get(authKey);
                }
                auth = Entity.newBuilder(authKey)
                                .set("username", at.username)
                                .set("role", role)
                                .set("creation_date", at.creationDate).set("expiration_date",at.expirationDate)
                                .build();
                txn.put(auth);
                txn.commit();
                LOG.info("User " + user.username + " logged in sucessfully.");
                return Response.ok(g.toJson(at)).build();
            } else {
                txn.rollback();
                LOG.warning("Wrong password for username: " + user.username);
                return Response.status(Status.FORBIDDEN).build();
            }
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

}
