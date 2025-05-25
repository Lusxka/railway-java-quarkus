package org.acme.app.security;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class ApiKeyService {

    @ConfigProperty(name = "quarkus.api-key.value")
    String validApiKey;

    public boolean isValid(String apiKey) {
        return apiKey != null && apiKey.equals(validApiKey);
    }

    public String getUsernameFromApiKey(String apiKey) {
        // In a real application, you might want to decode the API key
        // or look up user information from a database
        return "api-user";
    }

    public String[] getRolesFromApiKey(String apiKey) {
        // In a real application, you might want to retrieve roles
        // based on the API key from a database
        return new String[]{"user"};
    }
}