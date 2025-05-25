package org.acme.app.security;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.HttpHeaders;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class SecurityIdentityAugmentor implements SecurityIdentityAugmentor {

    @Inject
    ApiKeyService apiKeyService;

    @ConfigProperty(name = "quarkus.api-key.header-name")
    String apiKeyHeader;

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        return Uni.createFrom().item(() -> {
            String apiKey = context.getHttpHeaders().getHeaderString(apiKeyHeader);
            
            if (apiKey != null && apiKeyService.isValid(apiKey)) {
                QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder()
                    .setPrincipal(() -> apiKeyService.getUsernameFromApiKey(apiKey));
                
                for (String role : apiKeyService.getRolesFromApiKey(apiKey)) {
                    builder.addRole(role);
                }
                
                return builder.build();
            }
            
            return identity;
        });
    }
}