package pt.unl.fct.di.apdc.aval.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.aval.utils.LoginData;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.Filter;
import com.google.appengine.api.datastore.Query.FilterPredicate;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static com.google.cloud.datastore.ListValue.*;

@Path("/list")
public class ListResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private final Gson g = new Gson();
    public ListResource() {
    }

    @GET
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
    public Response listUsers(LoginData user) {
        LOG.fine("Attempt to list users");
        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = userKeyFactory.newKey(user.username);
            Entity user2 = txn.get(userKey);
            if (user2 == null) {
                txn.rollback();
                return Response.status(Status.BAD_REQUEST).entity("Error: Username does not exist").build();
            }
            String confirmation = user2.getString("password");
            if (!confirmation.equals(DigestUtils.sha512Hex(user.password)))
                return Response.status(Status.NOT_ACCEPTABLE).entity("Error: Wrong password").build();

            Query<Entity> query = null;
            QueryResults<Entity> results = null;
            List<Entity> list = null;
            switch (user2.getString("role")) {
                case "User":
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .setFilter(
                                    CompositeFilter.and(
                                            PropertyFilter.ge("role", "User"),
                                            PropertyFilter.ge("active", true),
                                            PropertyFilter.ge("public", true)
                                    )
                            ).build();
                    break;
                case "GBO":
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .setFilter(
                                    PropertyFilter.ge("role", "User")
                            ).build();
                    break;
                case "GS":
                    List<Value<String>> l = new ArrayList<>();
                    l.add(StringValue.of("User"));
                    l.add(StringValue.of("GBO"));

                    ListValue listValue = ListValue.newBuilder().set(l)
                            .build();
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .setFilter(
                                    PropertyFilter.in("role", listValue)
                            ).build();
                    break;
                case "SU":
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .build();
                    break;
                default:
                    return Response.status(Status.BAD_REQUEST).entity("Error: Try again later").build();
            }
            results = datastore.run(query);
            list = new ArrayList<>();
            results.forEachRemaining(list::add);
            return Response.ok(g.toJson(list)).build();

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
