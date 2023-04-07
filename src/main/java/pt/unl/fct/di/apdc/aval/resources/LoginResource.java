package pt.unl.fct.di.apdc.aval.resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.aval.utils.AuthToken;
import pt.unl.fct.di.apdc.aval.utils.LoginData;

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
    @Path("")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(LoginData user,
                          @Context HttpServletRequest request,
                          @Context HttpHeaders headers) {
        LOG.fine("Attempt to login user: " + user.username);
        Key userKey = userKeyFactory.newKey(user.username);
        Key ctrlKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", user.username))
                .setKind("UserStats").newKey("counters");
        Key logKey = datastore.allocateId(
                datastore.newKeyFactory().addAncestors(PathElement.of("User", user.username))
                        .setKind("UserLog").newKey()
        );
        Transaction txn = datastore.newTransaction();
        try{
            Entity user2 = txn.get(userKey);
            if(user2 == null){
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            Entity stats = txn.get(ctrlKey);
            if(stats == null) {
                stats = Entity.newBuilder(ctrlKey)
                        .set("user_first_login", Timestamp.now())
                        .set("user_last_login", Timestamp.now()).build();
            }
            String confirmation = user2.getString("password");
            if(confirmation.equals(DigestUtils.sha512Hex(user.password))) {
                Entity log = Entity.newBuilder(logKey)
                        .set("user_login_ip", request.getRemoteAddr())
                        .set("user_login_host", request.getRemoteHost())
                        .set("user_login_latlon",
                                StringValue.newBuilder(headers.getHeaderString("X-AppEngine-CityLatLong"))
                                        .setExcludeFromIndexes(true).build())
                        .set("user_login_city", headers.getHeaderString("X-AppEngine-City"))
                        .set("user_login_country", headers.getHeaderString("X-AppEngine-Country"))
                        .set("user_login_time", Timestamp.now()).build();

                Entity ustats = Entity.newBuilder(ctrlKey)
                        .set("user_first_login", stats.getTimestamp("user_first_login"))
                        .set("user_last_login", Timestamp.now()).build();
                AuthToken at = new AuthToken(user.username, user2.getString("role"));
                Key authKey = datastore.newKeyFactory().setKind("Token").newKey(at.tokenID);
                Entity auth = txn.get(authKey);
                while(auth != null) {
                    at = new AuthToken(user.username, user2.getString("role"));
                    authKey = datastore.newKeyFactory().setKind("Token").newKey(at.tokenID);
                    auth = txn.get(authKey);
                }
                auth = Entity.newBuilder(authKey)
                                .set("username", at.username)
                                .set("role", at.role)
                                .set("creation_date", at.creationDate).set("expiration_data",at.expirationDate)
                                .build();
                txn.put(log, ustats, auth);
                txn.commit();
                LOG.info("User " + user.username + " logged in sucessfully.");
                return Response.ok(g.toJson(at)).build();
            } else {
                Entity ustats = Entity.newBuilder(ctrlKey)
                        .set("user_first_login", stats.getTimestamp("user_first_login"))
                        .set("user_last_login", stats.getTimestamp("user_last_login"))
                        .set("user_last_attempt", Timestamp.now()).build();
                txn.put(ustats);
                txn.commit();
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
