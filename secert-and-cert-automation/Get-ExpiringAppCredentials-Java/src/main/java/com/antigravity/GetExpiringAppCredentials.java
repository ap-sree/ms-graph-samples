package com.antigravity;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.microsoft.graph.models.Application;
import com.microsoft.graph.models.ServicePrincipal;
import com.microsoft.graph.models.KeyCredential;
import com.microsoft.graph.models.PasswordCredential;
import com.microsoft.graph.serviceclient.GraphServiceClient;
import com.microsoft.graph.core.tasks.PageIterator;

import com.microsoft.graph.models.ApplicationCollectionResponse;
import com.microsoft.graph.models.ServicePrincipalCollectionResponse;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.lang.reflect.InvocationTargetException;

public class GetExpiringAppCredentials {

    private static final String TENANT_ID      = "TENANT_ID";
    private static final String CLIENT_ID      = "CLIENT_ID";
    private static final String CLIENT_SECRET  = "CLIENT_SECRET";
    private static final int    THRESHOLD_DAYS = 30;

    public static void main(String[] args) {

        // ---------------------------------------------------------------
        // Step 1: Build GraphServiceClient — SDK handles token acquisition
        // ---------------------------------------------------------------
        ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .tenantId(TENANT_ID)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .build();

        GraphServiceClient graphClient = new GraphServiceClient(
                credential, new String[]{"https://graph.microsoft.com/.default"});

        // ---------------------------------------------------------------
        // Step 2: Scan Applications
        // ---------------------------------------------------------------
        System.out.println("Scanning Applications...");
        var appsPage = graphClient.applications()
                .get(config -> config.queryParameters.select =
                        new String[]{"id", "appId", "displayName",
                                     "passwordCredentials", "keyCredentials"});

        PageIterator<Application, ApplicationCollectionResponse> appIterator = null;
        try {
            appIterator = new PageIterator
                    .Builder<Application, ApplicationCollectionResponse>()
                    .client(graphClient)
                    .collectionPage(appsPage)
                    .processPageItemCallback(app -> {
                        processCredentials(
                            app.getDisplayName(), app.getAppId(),
                            app.getPasswordCredentials(), app.getKeyCredentials(),
                            "Application"
                        );
                        return true;
                    })
                    .requestConfigurator(b -> b)
                    .collectionPageFactory(ApplicationCollectionResponse::createFromDiscriminatorValue)
                    .build();
        } catch (InvocationTargetException e) {
            System.err.println("Error building Application PageIterator (Invocation): " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (ReflectiveOperationException e) {
            System.err.println("Error building Application PageIterator (Reflection): " + e.getMessage());
            e.printStackTrace();
            return;
        }
        try {
            appIterator.iterate();
        } catch (ReflectiveOperationException e) {
            System.err.println("Error iterating Application pages: " + e.getMessage());
            e.printStackTrace();
        }

        // ---------------------------------------------------------------
        // Step 3: Scan Service Principals — filter type 'Application' only
        // servicePrincipalType eq 'Application' excludes ManagedIdentity,
        // Legacy and SocialIdp service principals
        // ---------------------------------------------------------------
        System.out.println("\nScanning Service Principals (type: Application)...");
        var spPage = graphClient.servicePrincipals()
                .get(config -> {
                    config.queryParameters.filter = "servicePrincipalType eq 'Application'";
                    config.queryParameters.select = new String[]{
                        "id", "appId", "displayName",
                        "passwordCredentials", "keyCredentials"};
                });

        PageIterator<ServicePrincipal, ServicePrincipalCollectionResponse> spIterator = null;
        try {
            spIterator = new PageIterator
                    .Builder<ServicePrincipal, ServicePrincipalCollectionResponse>()
                    .client(graphClient)
                    .collectionPage(spPage)
                    .processPageItemCallback(sp -> {
                        processCredentials(
                            sp.getDisplayName(), sp.getAppId(),
                            sp.getPasswordCredentials(), sp.getKeyCredentials(),
                            "ServicePrincipal"
                        );
                        return true;
                    })
                    .requestConfigurator(b -> b)
                    .collectionPageFactory(ServicePrincipalCollectionResponse::createFromDiscriminatorValue)
                    .build();
        } catch (InvocationTargetException e) {
            System.err.println("Error building ServicePrincipal PageIterator (Invocation): " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (ReflectiveOperationException e) {
            System.err.println("Error building ServicePrincipal PageIterator (Reflection): " + e.getMessage());
            e.printStackTrace();
            return;
        }
        try {
            spIterator.iterate();
        } catch (ReflectiveOperationException e) {
            System.err.println("Error iterating ServicePrincipal pages: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\nScan complete.");
        System.exit(0);
    }

    // ---------------------------------------------------------------
    // Process passwordCredentials and keyCredentials for any object
    // ---------------------------------------------------------------
    private static void processCredentials(String displayName, String appId,
                                            List<PasswordCredential> secrets,
                                            List<KeyCredential> certs,
                                            String source) {
        if (secrets != null) {
            for (PasswordCredential s : secrets) {
                evaluate(displayName, appId,
                        s.getDisplayName(),
                        s.getKeyId() != null ? s.getKeyId().toString() : "N/A",
                        s.getEndDateTime(), "Secret", source);
            }
        }

        if (certs != null) {
            for (KeyCredential c : certs) {
                String thumbprint = c.getCustomKeyIdentifier() != null
                        ? bytesToHex(c.getCustomKeyIdentifier()) : "N/A";
                evaluate(displayName, appId,
                        c.getDisplayName() != null ? c.getDisplayName() : c.getType(),
                        thumbprint, c.getEndDateTime(), "Certificate", source);
            }
        }
    }

    // ---------------------------------------------------------------
    // Evaluate expiry and notify
    // ---------------------------------------------------------------
    private static void evaluate(String appName, String appId, String credName,
                                  String id, OffsetDateTime endDateTime,
                                  String type, String source) {
        if (endDateTime == null) return;

        long days = ChronoUnit.DAYS.between(OffsetDateTime.now(), endDateTime);

        if (days < 0) {
            System.out.printf("[EXPIRED]       [%s] App: %-35s | Type: %-12s | Name: %-20s | Expired %d days ago%n",
                    source, appName, type, credName, Math.abs(days));
            sendNotification(appName, type, credName, days, source);
        } else if (days <= THRESHOLD_DAYS) {
            System.out.printf("[EXPIRING SOON] [%s] App: %-35s | Type: %-12s | Name: %-20s | Expires in %d days%n",
                    source, appName, type, credName, days);
            sendNotification(appName, type, credName, days, source);
        }
    }

    // ---------------------------------------------------------------
    // Notification hook — plug in email, Teams webhook, etc.
    // ---------------------------------------------------------------
    private static void sendNotification(String appName, String type,
                                          String credName, long days, String source) {
        // TODO: Integrate with notification system
        // e.g. SMTP email, Teams webhook, PagerDuty, Jira ticket
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
