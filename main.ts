import {
  defineApp,
  http,
  kv,
  lifecycle,
  AppInput,
  AppLifecycleCallbackOutput,
  AppOnHTTPRequestInput,
} from "@slflows/sdk/v1";

// Key value store keys
const KV_KEYS = {
  PRIVATE_KEY: "privateKey",
  PUBLIC_KEY: "publicKey",
  KEY_ID: "keyId",
  EXPIRES_AT: "expiresAt",
  CONFIG_CHECKSUM: "configChecksum",
};

// Constants
const REFRESH_BUFFER_SECONDS = 300; // Refresh 5 minutes before expiration
const DEFAULT_DURATION_SECONDS = 3600; // Default duration (1 hour)
const KEY_SIZE = 2048; // RSA key size
const ALGORITHM = "RS256"; // JWT algorithm

export const app = defineApp({
  name: "GCP Workload Identity Federation",

  signals: {
    accessToken: {
      name: "GCP Access Token",
      description: "GCP access token for API authentication",
      sensitive: true,
    },
    expiresAt: {
      name: "Token Expiration",
      description: "Unix timestamp (milliseconds) when token expires",
    },
  },

  installationInstructions: `To set up this GCP Workload Identity Federation app with OIDC:

1. **Configure the installation first**:
   - Leave the "Service Account Email" field empty for now
   - Fill out the rest of the settings (Project ID, etc.)
   - **Confirm the installation!**
   - The installation will show "In progress" status with message "Continue setup"

2. **Create a GCP Workload Identity Pool**:
   - Go to GCP Console → IAM & Admin → Workload Identity Federation
   - Create a new Workload Identity Pool (note the POOL_ID you choose)
   - Add a provider with these settings:
     - Provider type: OpenID Connect (OIDC)
     - Provider ID: Choose an ID (e.g., "flows-oidc-provider")
     - Issuer URL: set to <copyable>\`{appEndpointUrl}\`</copyable>
     - Allowed audiences: set to <copyable>\`{appEndpointUrl}\`</copyable>
     - Attribute mapping:
       - google.subject = assertion.sub
       - attribute.aud = assertion.aud

3. **Create or configure a Service Account**:
   - Create a new service account or use existing
   - Grant it the necessary permissions/roles for your use case
   - Note the service account email (format: name@project-id.iam.gserviceaccount.com)

4. **Grant Workload Identity User role**:
   - Go to the service account's IAM permissions page
   - Click "Grant Access" and add a new principal:
     - Principal: <copyable>\`principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.aud/{appEndpointUrl}\`</copyable>
     - Role: "Workload Identity User" (roles/iam.workloadIdentityUser)

5. **Complete the installation configuration**:
   - Copy the service account email
   - Copy the full Workload Identity Provider resource name (format: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID)
   - Return to this installation and paste both values into the configuration
   - Save the configuration - the installation should now succeed and start providing tokens
   - Note that **it takes a few moments for GCP permissions to propagate**, so if the status shows "failed" initially, wait a bit and try syncing again

6. **Use the tokens**:
   - The installation exposes GCP access tokens as signals that other installations can consume
   - Tokens are automatically refreshed before expiration`,

  config: {
    projectId: {
      name: "GCP Project ID",
      description: "Google Cloud Project ID",
      type: "string",
      required: true,
    },
    serviceAccountEmail: {
      name: "Service Account Email (initially empty)",
      description:
        "Email of the service account to impersonate. Leave empty initially - you'll fill this after creating the Workload Identity Pool and granting permissions.",
      type: "string",
      required: false,
    },
    workloadIdentityProvider: {
      name: "Workload Identity Provider Path",
      description:
        "Full resource path to the Workload Identity Provider (format: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID)",
      type: "string",
      required: false,
    },
    scopes: {
      name: "OAuth Scopes",
      description:
        "List of OAuth 2.0 scopes to request (default: cloud-platform for full access)",
      type: ["string"],
      required: false,
      default: ["https://www.googleapis.com/auth/cloud-platform"],
    },
    durationSeconds: {
      name: "Token Duration (seconds)",
      description: `Duration of access token in seconds (default ${DEFAULT_DURATION_SECONDS})`,
      type: "number",
      required: false,
      default: DEFAULT_DURATION_SECONDS,
    },
  },

  async onSync(input: AppInput): Promise<AppLifecycleCallbackOutput> {
    try {
      const config = input.app.config;

      // Validate required config
      if (!config.projectId) {
        return {
          newStatus: "failed",
          customStatusDescription: "Missing required Project ID",
        };
      }

      // Check if we need to generate keys
      await ensureKeyPair();

      if (!config.serviceAccountEmail || !config.workloadIdentityProvider) {
        return {
          newStatus: "in_progress",
          customStatusDescription: "Continue setup",
        };
      }

      // Validate the workloadIdentityProvider format
      if (!config.workloadIdentityProvider.includes("/providers/")) {
        return {
          newStatus: "failed",
          customStatusDescription:
            "Invalid Workload Identity Provider format. Must include /providers/PROVIDER_ID. Expected: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
        };
      }

      // Check if credentials need refresh
      const needsRefresh = await shouldRefreshCredentials(config);

      if (!needsRefresh) {
        // Credentials still valid, no update needed
        return { newStatus: "ready" };
      }

      // Generate new credentials
      const newCredentials = await generateCredentials(
        config,
        input.app.http.url,
      );

      return {
        newStatus: "ready",
        signalUpdates: {
          accessToken: newCredentials.accessToken,
          expiresAt: newCredentials.expiresAt,
        },
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      console.error("Failed to sync GCP Workload Identity app: ", errorMessage);

      return {
        newStatus: "failed",
        customStatusDescription: `Workload Identity sync failed: ${errorMessage}`,
      };
    }
  },

  http: {
    async onRequest(input: AppOnHTTPRequestInput): Promise<void> {
      const requestPath = input.request.path;

      try {
        if (requestPath === "/.well-known/openid-configuration") {
          // OIDC discovery endpoint
          const response = await handleOidcDiscovery(input.app.http.url);
          await http.respond(input.request.requestId, response);
        } else if (requestPath === "/.well-known/jwks") {
          // JWKS endpoint
          const response = await handleJwks();
          await http.respond(input.request.requestId, response);
        } else {
          await http.respond(input.request.requestId, {
            statusCode: 404,
            body: { error: "Endpoint not found" },
          });
        }
      } catch (error) {
        console.error("HTTP request failed: ", error);
        await http.respond(input.request.requestId, {
          statusCode: 500,
          body: { error: "Internal server error" },
        });
      }
    },
  },

  schedules: {
    "refresh-credentials": {
      description: "Refreshes GCP access token before it expires",
      customizable: false,
      definition: {
        type: "frequency",
        frequency: {
          interval: 10,
          unit: "minutes",
        },
      },
      async onTrigger() {
        try {
          const { value: expiresAt } = await kv.app.get(KV_KEYS.EXPIRES_AT);

          if (!expiresAt) {
            await lifecycle.sync();
            return;
          }

          const now = Date.now();
          const refreshThreshold = now + REFRESH_BUFFER_SECONDS * 1000;

          if (expiresAt < refreshThreshold) {
            await lifecycle.sync();
          }
        } catch (error) {
          console.error("Error in credential refresh schedule: ", error);
        }
      },
    },
  },

  blocks: {},
});

// Helper Functions

async function ensureKeyPair(): Promise<void> {
  // Check if all key components exist
  const [{ value: privateKey }, { value: publicKey }, { value: keyId }] =
    await kv.app.getMany([
      KV_KEYS.PRIVATE_KEY,
      KV_KEYS.PUBLIC_KEY,
      KV_KEYS.KEY_ID,
    ]);

  // Only generate keys if any component is missing
  if (!privateKey || !publicKey || !keyId) {
    // Generate RSA key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: KEY_SIZE,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );

    // Export keys
    const privateKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey,
    );
    const publicKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.publicKey,
    );

    // Generate stable key ID (use a deterministic approach)
    const newKeyId = crypto.randomUUID();

    // Store keys atomically - all or nothing
    await kv.app.setMany([
      { key: KV_KEYS.PRIVATE_KEY, value: privateKeyJwk },
      { key: KV_KEYS.PUBLIC_KEY, value: publicKeyJwk },
      { key: KV_KEYS.KEY_ID, value: newKeyId },
    ]);
  }
}

async function shouldRefreshCredentials(config: any): Promise<boolean> {
  const [{ value: expiresAt }, { value: previousChecksum }] =
    await kv.app.getMany([KV_KEYS.EXPIRES_AT, KV_KEYS.CONFIG_CHECKSUM]);

  // Check if config changed
  const currentChecksum = await generateChecksum(config);
  const configChanged =
    !previousChecksum || currentChecksum !== previousChecksum;

  // Check if credentials expired or close to expiring
  const now = Date.now();
  const refreshThreshold = now + REFRESH_BUFFER_SECONDS * 1000;
  const needsRefresh = !expiresAt || expiresAt < refreshThreshold;

  // Refresh if config changed or expiring soon
  return configChanged || needsRefresh;
}

async function generateCredentials(config: any, appUrl: string) {
  try {
    // Create OIDC token
    const oidcToken = await createOidcToken(appUrl);

    // Construct the audience for GCP STS token exchange
    // This should be the full resource name of the Workload Identity Provider
    const workloadProviderResourceName = `//iam.googleapis.com/${config.workloadIdentityProvider}`;

    // Exchange the OIDC token for a GCP access token
    const response = await fetch("https://sts.googleapis.com/v1/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        audience: workloadProviderResourceName,
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        subject_token: oidcToken,
        scope: (
          config.scopes || ["https://www.googleapis.com/auth/cloud-platform"]
        ).join(" "),
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `GCP STS token exchange failed: ${response.status} ${errorText}`,
      );
    }

    const stsToken = await response.json();

    // Impersonate service account to get final access token
    const impersonateResponse = await fetch(
      `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${config.serviceAccountEmail}:generateAccessToken`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${stsToken.access_token}`,
        },
        body: JSON.stringify({
          scope: config.scopes || [
            "https://www.googleapis.com/auth/cloud-platform",
          ],
          lifetime: `${config.durationSeconds || DEFAULT_DURATION_SECONDS}s`,
        }),
      },
    );

    if (!impersonateResponse.ok) {
      const errorText = await impersonateResponse.text();
      throw new Error(
        `Service account impersonation failed: ${impersonateResponse.status} ${errorText}`,
      );
    }

    const impersonateResult = await impersonateResponse.json();

    // Parse expiration time
    const expiresAt = new Date(impersonateResult.expireTime).getTime();

    // Store credentials and config checksum
    const configChecksum = await generateChecksum(config);
    await kv.app.setMany([
      { key: KV_KEYS.EXPIRES_AT, value: expiresAt },
      { key: KV_KEYS.CONFIG_CHECKSUM, value: configChecksum },
    ]);

    return {
      accessToken: impersonateResult.accessToken,
      expiresAt,
    };
  } catch (error) {
    console.error(
      "GCP Workload Identity failed: ",
      error instanceof Error ? error.message : String(error),
    );
    throw error;
  }
}

async function createOidcToken(appUrl: string): Promise<string> {
  const { value: privateKeyJwk } = await kv.app.get(KV_KEYS.PRIVATE_KEY);
  const { value: keyId } = await kv.app.get(KV_KEYS.KEY_ID);

  if (!privateKeyJwk || !keyId) {
    throw new Error("Private key or key ID not found");
  }

  // Import private key
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  // Create JWT header
  const header = {
    alg: ALGORITHM,
    typ: "JWT",
    kid: keyId,
  };

  const appHostname = new URL(appUrl).hostname;

  // Create JWT payload
  // For GCP Workload Identity Federation, the audience must match what's configured in the provider
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: appUrl,
    sub: appHostname,
    aud: appUrl, // Use full URL as audience to match Workload Identity Provider config
    exp: now + 300, // Token expires in 5 minutes
    iat: now,
    nbf: now,
    jti: crypto.randomUUID(),
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  // Create signature
  const signatureData = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signatureData),
  );

  const encodedSignature = base64UrlEncode(signature);

  return `${signatureData}.${encodedSignature}`;
}

async function handleOidcDiscovery(appUrl: string) {
  const discoveryDoc = {
    issuer: appUrl,
    jwks_uri: `${appUrl}/.well-known/jwks`,
    response_types_supported: ["id_token"],
    subject_types_supported: ["pairwise", "public"],
    id_token_signing_alg_values_supported: [ALGORITHM],
    claims_supported: ["sub", "aud", "exp", "iat", "iss", "jti", "nbf"],
  };

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: discoveryDoc,
  };
}

async function handleJwks() {
  const { value: publicKeyJwk } = await kv.app.get(KV_KEYS.PUBLIC_KEY);
  const { value: keyId } = await kv.app.get(KV_KEYS.KEY_ID);

  if (!publicKeyJwk || !keyId) {
    throw new Error("Public key or key ID not found");
  }

  // Match the working OIDC app format - only include essential JWK fields
  const jwks = {
    keys: [
      {
        kid: keyId,
        kty: "RSA",
        n: publicKeyJwk.n,
        e: publicKeyJwk.e,
      },
    ],
  };

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: jwks,
  };
}

function base64UrlEncode(data: string | ArrayBuffer): string {
  let base64: string;

  if (typeof data === "string") {
    base64 = btoa(data);
  } else {
    base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  }

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateChecksum(obj: any): Promise<string> {
  const configString = JSON.stringify(obj);
  const buffer = new TextEncoder().encode(configString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);

  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
