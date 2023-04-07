package pt.unl.fct.di.apdc.aval.resources;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.Entity.Builder;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.aval.utils.LoginData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@Path("/update")
public class UpdateResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    public UpdateResource() {
    }

    @PUT
    @Path("{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response updateUser(@PathParam("username") String id,
                               @FormParam("attribute") String attribute,
                               @FormParam("change") Value<?> change) {
        LOG.fine("Attempt to update user: " + user.username);
        Transaction txn = datastore.newTransaction();
        try{
            Key userKey = userKeyFactory.newKey(user.username);
            Entity user2 = txn.get(userKey);
            Key updateKey = userKeyFactory.newKey(username);
            Entity update = txn.get(updateKey);
            if(user2 == null || update == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            String confirmation = user2.getString("password");
            if (!confirmation.equals(DigestUtils.sha512Hex(user.password)))
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Error: Wrong password").build();
            if(attribute.equals("username") || attribute.equals("password"))
                return Response.status(Response.Status.BAD_REQUEST).entity("Cannot change attribute").build();

            String delRole = update.getString("role");
            switch (user2.getString("role")) {
                case "User":
                    if(attribute.equals("email") || attribute.equals("name"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Cannot change attribute").build();
                    if(!user.username.equals(username))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Don't have permissions").build();
                    break;
                case "GBO":
                    if(!delRole.equals("User"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "GS":
                    if(!delRole.equals("User") && !delRole.equals("GBO"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                default:
                    return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            Builder newUB = Entity.newBuilder(updateKey);
            Map<String, Value<?>> properties = update.getProperties();
            for(String att: properties.keySet()) {
                if(att.equals(attribute)) {
                    newUB.set(attribute, change);
                } else {
                    newUB.set(attribute, (Value<?>) user2.getValue(attribute));
                }
            }
            Entity newU = newUB.build();
            datastore.update(newU);
            LOG.fine("User updated: " + username);
            return Response.ok().build();
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

    private Response validPwd(String password, String confirmation) {
        Pattern specialChars = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);
        Pattern upperCase = Pattern.compile("[A-Z ]");
        Pattern digitCase = Pattern.compile("[0-9 ]");
        if(!password.equals(confirmation))
            return Response.status(Response.Status.NOT_ACCEPTABLE)
                    .entity("Passwords do not match").build();
        if(password.length() < 7)
            return Response.status(Response.Status.NOT_ACCEPTABLE)
                    .entity("Password length must be at least 7 characters").build();
        if(!specialChars.matcher(password).find())
            return Response.status(Response.Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 special character").build();
        if(!upperCase.matcher(password).find())
            return Response.status(Response.Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 upper case character").build();
        if(!digitCase.matcher(password).find())
            return Response.status(Response.Status.NOT_ACCEPTABLE)
                    .entity("Password must have at least 1 digit character").build();
        return Response.ok().entity("Password is valid").build();
    }

    @PUT
    @Path("/password")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response updatePwd(LoginData user, String newPwd, String confirmation) {
        LOG.fine("Attempt to update password of user: " + user.username);
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(user.username);
            Entity user2 = txn.get(userKey);
            if(user2 == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }

            String c = user2.getString("password");
            if (!c.equals(DigestUtils.sha512Hex(user.password)))
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Error: Wrong password").build();

            Response pwdValidation = validPwd(newPwd, confirmation);
            if(pwdValidation.getStatus() != Response.Status.OK.getStatusCode())
                return pwdValidation;

            Builder newUB = Entity.newBuilder(userKey);
            Map<String, Value<?>> properties = user2.getProperties();
            for(String attribute: properties.keySet()) {
                if(attribute.equals("password")) {
                    newUB.set("password", newPwd);
                } else {
                    newUB.set(attribute, (Value<?>) user2.getValue(attribute));
                }
            }
            Entity newU = newUB.build();
            datastore.update(newU);
            LOG.fine("User updated: " + user.username);
            return Response.ok().build();
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
