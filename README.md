# GCP Workload Identity Federation - Flows App

Generate short-lived GCP access tokens using Workload Identity Federation with OIDC, providing secure, temporary credentials as signals for other apps to consume.

## Overview

This Flows app acts as an OIDC provider and exchanges OIDC tokens for GCP access tokens through Workload Identity Federation. It's the GCP equivalent of the AWS STS app, providing temporary credentials without storing long-lived service account keys.

**Key Features:**

- 🔐 **Secure Token Generation** - No long-lived credentials stored
- 🔄 **Automatic Refresh** - Tokens refreshed before expiration
- 🎯 **Signal-Based** - Tokens exposed as signals for other apps
- 🌐 **OIDC Provider** - Built-in OIDC discovery and JWKS endpoints
- 🛡️ **Service Account Impersonation** - Scoped access to GCP resources

## How It Works

```
┌─────────────────┐
│   Flows App     │
│  (OIDC Provider)│
└────────┬────────┘
         │ 1. Generate JWT
         │    (signed with RSA key)
         ▼
┌─────────────────┐
│  GCP Workload   │
│  Identity Pool  │◄──── 2. Validate JWT
└────────┬────────┘       (issuer, audience, signature)
         │
         │ 3. Exchange for federated token
         ▼
┌─────────────────┐
│   GCP STS API   │
└────────┬────────┘
         │
         │ 4. Impersonate service account
         ▼
┌─────────────────┐
│  Service Account│
│   Access Token  │◄──── 5. Return scoped token
└─────────────────┘
         │
         │ 6. Exposed as signal
         ▼
┌─────────────────┐
│  Other Flows    │
│      Apps       │
└─────────────────┘
```

## Installation & Setup

### Prerequisites

- GCP Project with Workload Identity Federation enabled
- Service Account with appropriate permissions
- Basic understanding of IAM and Workload Identity

### Step-by-Step Setup

#### 1. Initial App Configuration

1. Create a new installation of this app in Flows
2. Configure the **GCP Project ID**
3. Leave **Service Account Email** and **Workload Identity Provider** empty for now
4. **Confirm the installation** - it will show "In progress" status

#### 2. Create GCP Workload Identity Pool

```bash
# Create the pool
gcloud iam workload-identity-pools create myflowsapp \
  --location="global" \
  --display-name="Flows OIDC Pool"

# Note your PROJECT_NUMBER (not project ID)
gcloud projects describe YOUR_PROJECT_ID --format="value(projectNumber)"
```

Or via GCP Console:

1. Go to **IAM & Admin → Workload Identity Federation**
2. Click **Create Pool**
3. Name: `myflowsapp` (or your choice)
4. Click **Continue**

#### 3. Add OIDC Provider to Pool

Get your app endpoint URL from the Flows installation, then:

```bash
gcloud iam workload-identity-pools providers create-oidc flows-provider \
  --location="global" \
  --workload-identity-pool="myflowsapp" \
  --issuer-uri="https://your-app-endpoint.flows.liftspace.net" \
  --allowed-audiences="https://your-app-endpoint.flows.liftspace.net" \
  --attribute-mapping="google.subject=assertion.sub,attribute.aud=assertion.aud"
```

Or via GCP Console:

1. Click on your newly created pool
2. Click **Add Provider**
3. Select **OpenID Connect (OIDC)**
4. Provider ID: `flows-provider`
5. Issuer URL: Copy from your Flows installation (the full https://... URL)
6. Allowed audiences: Same as Issuer URL
7. Attribute mapping:
   - `google.subject` = `assertion.sub`
   - `attribute.aud` = `assertion.aud`
8. Click **Save**

#### 4. Create or Configure Service Account

```bash
# Create service account
gcloud iam service-accounts create flows-workload-sa \
  --display-name="Flows Workload Identity Service Account"

# Grant it permissions (example: compute viewer)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:flows-workload-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/compute.viewer"
```

Note the service account email: `flows-workload-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com`

#### 5. Grant Workload Identity User Role

```bash
gcloud iam service-accounts add-iam-policy-binding flows-workload-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/myflowsapp/attribute.aud/https://your-app-endpoint.flows.liftspace.net"
```

Or via GCP Console:

1. Go to **IAM & Admin → Service Accounts**
2. Click on your service account
3. Go to **PERMISSIONS** tab
4. Click **GRANT ACCESS**
5. New principals: `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.aud/YOUR_APP_URL`
6. Role: **Workload Identity User**
7. Click **SAVE**

#### 6. Get Provider Resource Name

```bash
gcloud iam workload-identity-pools providers describe flows-provider \
  --workload-identity-pool="myflowsapp" \
  --location="global" \
  --format="value(name)"
```

This will output something like:

```
projects/123456789/locations/global/workloadIdentityPools/myflowsapp/providers/flows-provider
```

#### 7. Complete App Configuration

Return to your Flows installation and update:

- **Service Account Email**: `flows-workload-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com`
- **Workload Identity Provider Path**: The full path from step 6
- **OAuth Scopes** (optional): Defaults to `cloud-platform` for full access
- **Token Duration** (optional): Defaults to 3600 seconds (1 hour)

Save the configuration - the app should transition to "ready" status!

**Note**: GCP permissions can take a few moments to propagate. If you see a permission denied error, wait 30-60 seconds and trigger a sync.

## Configuration Options

| Field                          | Type   | Required | Description                                                                                       |
| ------------------------------ | ------ | -------- | ------------------------------------------------------------------------------------------------- |
| **Project ID**                 | string | Yes      | Your GCP Project ID                                                                               |
| **Service Account Email**      | string | Yes      | Email of the service account to impersonate                                                       |
| **Workload Identity Provider** | string | Yes      | Full resource path: `projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` |
| **OAuth Scopes**               | array  | No       | OAuth 2.0 scopes (default: `cloud-platform`)                                                      |
| **Token Duration**             | number | No       | Token lifetime in seconds (default: 3600, max: depends on service account config)                 |

### Common OAuth Scopes

- `https://www.googleapis.com/auth/cloud-platform` - Full access (default)
- `https://www.googleapis.com/auth/compute` - Compute Engine
- `https://www.googleapis.com/auth/storage.read_write` - Cloud Storage
- `https://www.googleapis.com/auth/bigquery` - BigQuery
- `https://www.googleapis.com/auth/logging.write` - Cloud Logging

## Signals

The app exposes two signals that other Flows apps can consume:

### `accessToken`

- **Type**: string (sensitive)
- **Description**: GCP access token for API authentication
- **Usage**: Pass as `Bearer` token in Authorization header for GCP API calls
- **Example**: `Authorization: Bearer ya29.c.b0Aaekm1...`

### `expiresAt`

- **Type**: number
- **Description**: Unix timestamp (milliseconds) when token expires
- **Usage**: Monitor expiration, though automatic refresh is handled by the app

**Using the signals in other apps:**

The access token can be consumed by other Flows apps (like the HTTP Request app) to make authenticated calls to GCP APIs:

```
Authorization: Bearer {{signals.gcp_workload_identity.accessToken}}
```

## OIDC Endpoints

The app provides standard OIDC endpoints:

### Discovery Document

**GET** `/.well-known/openid-configuration`

Returns OIDC configuration including supported algorithms, claims, and JWKS URI.

### JSON Web Key Set

**GET** `/.well-known/jwks`

Returns the public keys used to verify JWT signatures.

## Security Considerations

### RSA Key Pair

- 2048-bit RSA keys generated and stored in app KV store
- Keys persist across restarts
- Private key never leaves the app environment

### JWT Tokens

- Short-lived (5 minutes)
- Signed with RS256 algorithm
- Include standard claims (iss, sub, aud, exp, iat, nbf, jti)

### Access Tokens

- Scoped to configured OAuth scopes
- Automatically refreshed 5 minutes before expiration
- Stored securely as sensitive signals

### Best Practices

1. **Principle of Least Privilege**: Grant service account only necessary permissions
2. **Scope Limitation**: Use specific OAuth scopes instead of `cloud-platform`
3. **Short Duration**: Keep token duration as short as practical
4. **Audit Logging**: Enable GCP audit logs for service account activity
5. **Regular Review**: Periodically review service account permissions

## Troubleshooting

### "Invalid value for audience"

**Issue**: The Workload Identity Provider path is incomplete.

**Solution**: Ensure the path includes `/providers/PROVIDER_ID`:

```
projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider
```

### "Permission denied: iam.serviceAccounts.getAccessToken"

**Issue**: Service account doesn't have Workload Identity User role.

**Solution**: Grant the role with the principal set:

```bash
gcloud iam service-accounts add-iam-policy-binding SA_EMAIL \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/attribute.aud/APP_URL"
```

### "Issuer not found" or "Invalid issuer"

**Issue**: OIDC provider configuration doesn't match JWT claims.

**Solution**:

1. Verify Issuer URL in GCP exactly matches your app endpoint URL
2. Check Allowed audiences includes your app endpoint URL
3. Ensure both use the full https://... URL format

### Permissions take time to propagate

**Issue**: Configuration looks correct but still getting permission errors.

**Solution**: GCP IAM bindings can take 60-120 seconds to propagate. Wait a couple of minutes and retry.

### Token refresh not working

**Issue**: Tokens not being refreshed automatically.

**Solution**:

1. Check schedule is enabled (should be automatic)
2. Verify app has `expiresAt` signal value stored
3. Check app logs for refresh schedule errors

## Development

### Prerequisites

- Node.js 20+
- TypeScript 5.8+
- npm

### Setup

```bash
npm install
npm run typecheck
npm run format
```

### Scripts

- `npm run typecheck` - Type checking
- `npm run format` - Code formatting
- `npm run bundle` - Create deployment bundle

### Project Structure

```
flows-app-gcp-workflow-identity-federation/
├── main.ts                 # App definition and core logic
├── package.json
├── tsconfig.json
└── README.md
```

## Comparison with AWS STS App

| Feature            | AWS STS                             | GCP Workload Identity                    |
| ------------------ | ----------------------------------- | ---------------------------------------- |
| **Token Type**     | Access Key + Secret + Session Token | Access Token (Bearer)                    |
| **Authentication** | AWS Signature V4                    | Bearer Token                             |
| **Setup**          | OIDC Provider + IAM Role            | Workload Identity Pool + Service Account |
| **Permissions**    | IAM Role policies                   | Service Account IAM roles                |
| **Token Format**   | Three separate values               | Single token string                      |
| **API Signing**    | Required (SigV4)                    | Not required (Bearer token)              |

## Resources

- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [OIDC Providers in GCP](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
- [Service Account Impersonation](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct)
- [GCP STS API](https://cloud.google.com/iam/docs/reference/sts/rest)
- [OAuth 2.0 Scopes](https://developers.google.com/identity/protocols/oauth2/scopes)

## License

See repository license.

## Support

For issues and questions:

1. Check the Troubleshooting section above
2. Review GCP Workload Identity Federation documentation
3. Open an issue in the repository
