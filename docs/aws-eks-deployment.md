# Production deployment on AWS EKS

Reference manifests: `deploy/k8s/identity-federation.yaml` and `../core-authorization/deploy/k8s/core-authorization.yaml`.

## Topology

| Layer | Identity Federation | Core Authorization |
|---|---|---|
| Exposure | Public ALB (`identity.miqaat.com`), WAF, TLS 1.2+ | **Internal only** (ClusterIP / internal ALB) |
| Pods | ≥3 replicas across AZs, HPA 3–12, PDB minAvailable 2 | ≥3 replicas, HPA 3–10, PDB 2 |
| Database | Aurora PostgreSQL cluster **A** (`miqaat_auth`) | Aurora PostgreSQL cluster **B** (`miqaat_authz`) |
| Redis | ElastiCache (TLS, AUTH) **A**, Multi-AZ | ElastiCache **B** |
| Secrets | Secrets Manager: signing keys (IRSA) + DB credentials | Secrets Manager (DB) |

Separate clusters, security groups and IAM principals keep credentials and authorization data isolated.

## Checklist

1. **Build & push** images (`Dockerfile` in each repo) to ECR with immutable tags; scan with ECR/Inspector.
2. **Databases**: create both Aurora clusters (encryption at rest, IAM auth optional, deletion protection, PITR).
   Create least-privilege DB users (`identity_federation`, `core_authorization`) — DML only at runtime; a separate migration user if preferred.
3. **Migrations** run in the `initContainer` (`typeorm migration:run -d dist/database/data-source.js`); TypeORM takes a lock, so concurrent pods are safe.
4. **Signing keys**: create the KMS CMK, secret resource policy and IRSA role; bootstrap with `npm run keys:generate` using the rotation role. See `aws-signing-keys.md`.
5. **Service principals (no API keys)**: register `identity-federation` (FEDERATION, `jwks_uri` = Identity JWKS) and each BU backend (AUTHZ_CHECK + its client IDs, `jwks_uri` = the backend's JWKS) with `npm run principal:register`. BU private keys stay in each BU's own secret manager; nothing secret is shared with Core.
6. **Config**: `ISSUER=https://identity.miqaat.com`, `TRUST_PROXY=true`, `COOKIE_SECURE=true`, `SWAGGER_ENABLED=false`, `ALLOW_INSECURE_LOCALHOST_URIS=false`.
7. **Ingress**: only `/embed`, `/portal`, `/assets`, `/auth`, `/federation`, `/.well-known` are routed publicly. `/health*` stays internal.
8. **WAF**: rate-based rule on `POST /embed/login` and `/portal/login` per IP, AWS managed common/bad-inputs rule sets, geo rules if needed.
9. **Network**: RDS/ElastiCache in private subnets; VPC endpoints for Secrets Manager, KMS, ECR, CloudWatch; NetworkPolicy restricting Authorization ingress to the Identity namespace and labelled BU namespaces.
10. **Observability**: JSON logs → CloudWatch/OpenSearch (already redacted); alarms on `LOGIN_FAILED` rate, `TOO_MANY_ATTEMPTS`, `EMBED_LOGIN_REJECTED`, `BACKCHANNEL_LOGOUT` failures, 5xx, readiness failures, key reload errors.
11. **Back-channel egress**: allow HTTPS egress from Identity pods to registered `back_channel_logout_uri` hosts only.
12. **DR**: Aurora global database or cross-region snapshots; replicate the signing-key secret (Secrets Manager multi-Region replica); Redis loss only ends sessions (users sign in again).

## Scaling notes

* Identity pods are stateless (sessions/txns/rate limits in Redis); scrypt is CPU-bound — size CPU for peak logins
  (≈50–80 ms/verify per core at N=2^15).
* Authorization decisions are cached per `(its_id, client_id)` for 60 s with version-based invalidation; BU backends cache decisions ≤30 s.
* JWKS responses are cacheable (`max-age=300`); put CloudFront in front of `/.well-known/*` and `/assets/*` if desired.

## Zero-downtime changes

* Client configuration changes propagate within `CLIENT_CACHE_TTL_SECONDS` (30 s).
* Key rotation is online (stage → wait → promote → wait → retire).
* Rolling updates: `maxUnavailable: 0`; in-flight back-channel deliveries are drained on shutdown.
