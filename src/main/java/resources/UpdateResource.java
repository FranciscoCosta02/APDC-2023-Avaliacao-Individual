package resources;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.Entity.Builder;
import org.apache.commons.codec.digest.DigestUtils;
import filters.Secured;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@Path("/update")
public class UpdateResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
    public UpdateResource() {
    }

    @PUT
    @Secured
    @Path("/attributes{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUser(@PathParam("id") String id,
                               @FormParam("username") String username,
                               @FormParam("attribute") String attribute,
                               @FormParam("change") Value<?> change) {
        Transaction txn = datastore.newTransaction();
        try{
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Response.Status.BAD_REQUEST).entity("Not a valid Login.").build();
            }
            boolean changesForHimself = false;
            Entity user = datastore.get(datastore.newKeyFactory().setKind("User").newKey(token.getString("username")));
            if(username.equals(token.getString("username"))) {
                changesForHimself = true;
            }
            Entity userToUpdate = datastore.get(datastore.newKeyFactory().setKind("User").newKey(username));
            if(userToUpdate == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            LOG.fine("Attempt to update user: " + userToUpdate.getString("username"));
            if(attribute.equals("username")) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Cannot change attribute").build();
            }
            if(attribute.equals("password"))
                if(changesForHimself);

            String delRole = userToUpdate.getString("role");
            switch (user.getString("role")) {
                case "User":
                    if(!changesForHimself)
                        return Response.status(Response.Status.BAD_REQUEST).entity("Don't have permissions").build();
                    break;
                case "GBO":
                    if(!delRole.equals("USER"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "GS":
                    if(!delRole.equals("USER") && !delRole.equals("GBO"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "SU":
                    if(delRole.equals("SU"))
                        return Response.status(Response.Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                default:
                    return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            Builder newUB = Entity.newBuilder(userToUpdate.getKey());
            Map<String, Value<?>> properties = userToUpdate.getProperties();
            for(String att: properties.keySet()) {
                if(att.equals(attribute)) {
                    newUB.set(attribute, change);
                } else {
                    newUB.set(attribute, (Value<?>) user.getValue(attribute));
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
    @Path("/password{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response updatePwd(@PathParam("id") String id, String newPwd, String confirmation) {

        Transaction txn = datastore.newTransaction();
        try {
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Response.Status.BAD_REQUEST).entity("Not a valid Login.").build();
            }
            Entity user = datastore.get(datastore.newKeyFactory().setKind("User").newKey(token.getString("username")));
            if(user == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            LOG.fine("Attempt to update user: " + user.getString("username"));

            String c = user.getString("password");
            if (!c.equals(DigestUtils.sha512Hex(user.getString("password"))))
                return Response.status(Response.Status.NOT_ACCEPTABLE).entity("Error: Wrong password").build();

            Response pwdValidation = validPwd(newPwd, confirmation);
            if(pwdValidation.getStatus() != Response.Status.OK.getStatusCode())
                return pwdValidation;

            Builder newUB = Entity.newBuilder(user.getKey());
            Map<String, Value<?>> properties = user.getProperties();
            for(String attribute: properties.keySet()) {
                if(attribute.equals("password")) {
                    newUB.set("password", newPwd);
                } else {
                    newUB.set(attribute, (Value<?>) user.getValue(attribute));
                }
            }
            Entity newU = newUB.build();
            datastore.update(newU);
            LOG.fine("User updated: " + user.getString("username"));
            return Response.ok(Response.Status.OK).build();
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
