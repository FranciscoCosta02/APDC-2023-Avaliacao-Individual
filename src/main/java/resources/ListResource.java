package resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import filters.Secured;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;


import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;


@Path("/list")
public class ListResource {
    private static final Logger LOG = Logger.getLogger(ListResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
    private final Gson g = new Gson();
    public ListResource() {
    }

    @GET
    @Secured
    @Path("{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response listUsers(@PathParam("id") String id) {
        LOG.fine("Attempt to list users");
        Transaction txn = datastore.newTransaction();
        try {
            Key tokenKey = tokenKeyFactory.newKey(id);
            Entity token = txn.get(tokenKey);

            Query<Entity> query;
            QueryResults<Entity> results;
            List<Entity> list;
            switch (token.getString("role")) {
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
