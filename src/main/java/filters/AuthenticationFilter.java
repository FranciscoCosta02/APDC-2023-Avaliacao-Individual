package filters;

import com.google.cloud.datastore.*;
import resources.LoginResource;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.util.logging.Logger;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {
    private static final String REALM = "example";
    private static final String AUTHENTICATION_SCHEME = "Bearer";
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");

    @Override
    public void filter(ContainerRequestContext requestContext) {

        // Get the Authorization header from the request
        String authorizationHeader =
                requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        // Validate the Authorization header
        if (!isTokenBasedAuthentication(authorizationHeader)) {
            abortWithUnauthorized(requestContext);
            return;
        }

        // Extract the token from the Authorization header
        String token = authorizationHeader
                .substring(AUTHENTICATION_SCHEME.length()).trim();

        try {
            // Validate the token
            validateToken(token);

        } catch (Exception e) {
            abortWithUnauthorized(requestContext);
        }
    }

    private boolean isTokenBasedAuthentication(String authorizationHeader) {

        // Check if the Authorization header is valid
        // It must not be null and must be prefixed with "Bearer" plus a whitespace
        // The authentication scheme comparison must be case-insensitive
        return authorizationHeader != null && authorizationHeader.toLowerCase()
                .startsWith(AUTHENTICATION_SCHEME.toLowerCase() + " ");
    }

    private void abortWithUnauthorized(ContainerRequestContext requestContext) {

        // Abort the filter chain with a 401 status code response
        // The WWW-Authenticate header is sent along with the response
        requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                                AUTHENTICATION_SCHEME + " realm=\"" + REALM + "\"")
                        .build());
    }

    private void validateToken(String token) throws Exception {
        Transaction txn = datastore.newTransaction();
        Key tokenKey = tokenKeyFactory.newKey(token);
        try{
            Entity t = txn.get(tokenKey);
            if(t == null){
                txn.rollback();
                throw new Exception("Token does not exist");
            }
            long expirationDate = t.getLong("expiration_date");
            if(System.currentTimeMillis()>expirationDate) {
                txn.rollback();
                throw new Exception("Token is not longer valid");
            }
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            throw new Exception("Token is not valid");
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }

    }
}
