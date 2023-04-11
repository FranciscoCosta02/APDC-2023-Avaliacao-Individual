package resources;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.Entity.Builder;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
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
    @Path("/attributes")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUser(@Context HttpServletRequest request) {
        String id = request.getHeader("Authorization");
        id = id.substring("Bearer".length()).trim();
        String username = request.getHeader("Username");
        String attribute = request.getHeader("Attribute");
        String change = request.getHeader("Change");
        Transaction txn = datastore.newTransaction();
        try{
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Status.BAD_REQUEST).entity("Not a valid Login.").build();
            }
            Entity userToUpdate = datastore.get(datastore.newKeyFactory().setKind("User").newKey(username));
            if(userToUpdate == null) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            LOG.fine("Attempt to update user: " + username);
            if(attribute.equals("username") || attribute.equals("password")) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Cannot change attribute").build();
            }

            String delRole = userToUpdate.getString("role");
            switch (token.getString("role")) {
                case "User":
                    if(!username.equals(token.getString("username"))
                            || attribute.equals("email") || attribute.equals("name"))
                        return Response.status(Status.BAD_REQUEST).entity("Don't have permissions").build();
                    break;
                case "GBO":
                    if(!delRole.equals("USER"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "GS":
                    if(!delRole.equals("USER") && !delRole.equals("GBO"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                case "SU":
                    if(delRole.equals("SU"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                default:
                    return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            Builder newUB = Entity.newBuilder(userToUpdate.getKey());
            Map<String, Value<?>> properties = userToUpdate.getProperties();
            for(String att: properties.keySet()) {
                if(att.equals(attribute)) {
                    newUB.set(attribute, change);
                } else {
                    newUB.set(att, userToUpdate.getString(att));
                }
            }
            Entity newU = newUB.build();
            datastore.update(newU);
            txn.commit();
            LOG.fine("User updated: " + username);
            return Response.ok().build();
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Status.FORBIDDEN).entity(e.getMessage()).build();
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
    public Response updatePwd(@Context HttpServletRequest request) {
        String id = request.getHeader("Authorization");
        id = id.substring("Bearer".length()).trim();
        String password = request.getHeader("Password");
        String newPwd = request.getHeader("newPwd");
        String confirmation = request.getHeader("Confirmation");
        Transaction txn = datastore.newTransaction();
        try {
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Response.Status.BAD_REQUEST).entity("Not a valid Login.").build();
            }
            String username = token.getString("username");
            Entity user = datastore.get(datastore.newKeyFactory().setKind("User").newKey(username));
            if(user == null) {
                txn.rollback();
                return Response.status(Response.Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            LOG.fine("Attempt to update user: " + username);

            if (!user.getString("password").equals(DigestUtils.sha512Hex(password)))
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
                    newUB.set(attribute, user.getString(attribute));
                }
            }
            Entity newU = newUB.build();
            datastore.update(newU);
            txn.commit();
            LOG.fine("User updated: " + username);
            return Response.ok(Status.OK).build();
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Status.FORBIDDEN).entity(e.getMessage()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }
}
