package pt.unl.fct.di.apdc.aval.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.aval.utils.LoginData;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LogoutResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response login(LoginData user) {
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
            if(!confirmation.equals(DigestUtils.sha512Hex(user.password))) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Wrong password").build();
            }
    }
}
