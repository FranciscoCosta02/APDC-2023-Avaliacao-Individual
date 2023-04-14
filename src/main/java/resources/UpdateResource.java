package resources;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.Entity.Builder;
import org.apache.commons.codec.digest.DigestUtils;
import utils.UserData;

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
    public Response updateUser(@Context HttpServletRequest request, UserData user) {
        String id = request.getHeader("Authorization");
        id = id.substring("Bearer".length()).trim();
        Transaction txn = datastore.newTransaction();
        try{
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = datastore.get(tokenKey);
            if(token == null) {
                txn.rollback();
                return Response.ok(Status.BAD_REQUEST).entity("Not a valid Login.").build();
            }
            Key updateKey = datastore.newKeyFactory().setKind("User").newKey(user.username);
            Entity userToUpdate = datastore.get(updateKey);
            if(userToUpdate == null) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            LOG.fine("Attempt to update user: " + user.username);
            String delRole = userToUpdate.getString("role");
            switch (token.getString("role")) {
                case "User":
                    if(!user.username.equals(token.getString("username")))
                        return Response.status(Status.BAD_REQUEST).entity("Don't have permissions").build();
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
                    if(delRole.equals("SU"))
                        return Response.status(Status.BAD_REQUEST).entity("Error: Don't have permissions").build();
                    break;
                default:
                    return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            Entity user2 = Entity.newBuilder(updateKey)
                    .set("password", user.password)
                    .set("email",user.email).set("name", user.name)
                    .set("role", user.role).set("activity", user.activity)
                    .set("privacy", user.privacy).set("phone", user.phone)
                    .set("workplace", user.workplace).set("address", user.address)
                    .set("occupation", user.occupation).set("NIF", user.NIF)
                    .set("photo", user.photo).build();
            datastore.update(user2);
            txn.commit();
            LOG.fine("User updated: " + user.username);
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
        String password = request.getHeader("oldPwd");
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
                    newUB.set("password", DigestUtils.sha512Hex(newPwd));
                } else {
                    newUB.set(attribute, user.getString(attribute));
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
}
