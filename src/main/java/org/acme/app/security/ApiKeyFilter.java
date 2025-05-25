package org.acme.app.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Provider
@ApplicationScoped
public class ApiKeyFilter implements ContainerRequestFilter {

    @Inject
    ApiKeyService apiKeyService;

    @ConfigProperty(name = "quarkus.api-key.header-name", defaultValue = "X-API-Key")
    String apiKeyHeader;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String path = requestContext.getUriInfo().getPath();
        
        // Skip authentication for public endpoints
        if (isPublicPath(path)) {
            return;
        }

        String apiKey = requestContext.getHeaderString(apiKeyHeader);
        
        if (apiKey == null || !apiKeyService.isValid(apiKey)) {
            requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Invalid or missing API key")
                    .build()
            );
        }
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/public/") ||
               path.startsWith("/q/") ||  // Quarkus dev console and health endpoints
               path.equals("/swagger") ||
               path.equals("/openapi");
    }
}