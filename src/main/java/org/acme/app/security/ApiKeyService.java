package org.acme.app.security;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.util.Optional;

@ApplicationScoped
public class ApiKeyService {

    @ConfigProperty(name = "quarkus.api-key.value")
    String validApiKey;

    public boolean isValid(String apiKey) {
        if (apiKey == null || validApiKey == null) {
            return false;
        }
        return apiKey.equals(validApiKey);
    }

    public String getUsernameFromApiKey(String apiKey) {
        if (isValid(apiKey)) {
            return "api-user";
        }
        return null;
    }

    public String[] getRolesFromApiKey(String apiKey) {
        if (isValid(apiKey)) {
            return new String[]{"user"};
        }
        return new String[]{};
    }
}