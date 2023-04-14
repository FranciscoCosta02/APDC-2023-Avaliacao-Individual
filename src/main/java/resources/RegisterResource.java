package resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;
import utils.UserData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;

@Path("/register")
public class RegisterResource {

    private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    public RegisterResource() {
    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response registerUser(UserData user) {
            if(user.confirmInputs())
                return Response.status(Status.BAD_REQUEST)
                    .entity("At least one input is empty").build();
            if(!user.emailValid())
                return Response.status(Status.NOT_ACCEPTABLE)
                        .entity("Email format is invalid").build();
            Response pwdValidation = user.pwdValid();
            if(pwdValidation.getStatus() != Status.OK.getStatusCode())
                return pwdValidation;

            LOG.fine("Attempt to register user: " + user.username);
            Transaction txn = datastore.newTransaction();
            try{
                Key userKey = userKeyFactory.newKey(user.username);


                Entity user2 = txn.get(userKey);
                if(user2!=null) {
                    txn.rollback();
                    return Response.status(Status.NOT_ACCEPTABLE).entity("User already exists").build();
                }
                if(user.checkNull(user.privacy)) {
                    user.privacy = "public";
                }
                user2 = Entity.newBuilder(userKey).set("password", DigestUtils.sha512Hex(user.password))
                        .set("email",user.email).set("name", user.name)
                        .set("role", "User").set("activity", "Inactive")
                        .set("privacy", user.privacy).set("phone", user.phone)
                        .set("workplace", user.workplace).set("address", user.address)
                        .set("occupation", user.occupation).set("NIF", user.NIF)
                        .set("photo", user.photo).build();
                txn.put(user2);
                txn.commit();
                LOG.fine("User registered: " + user.username);
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
