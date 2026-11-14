# NexusAuth — Zero-Trust API Security Gateway & Telemetry Platform

**NexusAuth** is an enterprise-grade API Security Gateway, Cryptographic Key Management, and Telemetry Platform built with **ASP.NET Core MVC** and **Microsoft SQL Server**. Designed around zero-trust and defense-in-depth principles, NexusAuth governs how internal engineering teams and external B2B subscribers authenticate, consume, and monitor protected backend API resources.

---

## Core Capabilities

* **Zero-Trust API Gateway Middleware:** Intercepts incoming `X-Api-Key` headers, computes SHA-256 hashes, validates token status and expiration, enforces per-token IP allowlists, checks granular permission scopes, and applies sliding-window rate limits before routing requests.
* **Cryptographic Secret Hygiene:** User passwords are salted and hashed with **BCrypt**. API keys (`nx_live_...` / `nx_test_...`) are displayed **once** upon creation and persisted solely as a 16-character `KeyPrefix` and 64-character SHA-256 `TokenHash`.
* **Per-Token Server IP Allowlisting:** Binds individual API keys to authorized server IP addresses, blocking requests from unrecognized origins (`403 IP_NOT_ALLOWLISTED`) even if a secret key is compromised.
* **Atomic Key Rotation (`sp_RotateApiToken`):** Executes key revocation, replacement key generation, scope/rate-limit/IP inheritance, and audit logging inside an explicit T-SQL `TRANSACTION` block with row-level locking (`UPDLOCK`).
* **Tamper-Proof SQL Audit Trail:** Every state-changing event—including login attempts, key issuance/rotation/revocation, IP whitelist edits, and quota approvals—is recorded in `AuditLogs` with before/after JSON diffs, protected at the database engine level via `DENY UPDATE, DELETE`.
* **Automated Brute-Force Lockout:** Tracks consecutive failed authentication attempts per user, automatically locking accounts for 15 minutes after 5 failed attempts with Administrator unlock governance.
* **Quota Upgrade Approval Workflow:** Enables external subscribers to formally request rate-limit increases or additional active token slots, which Administrators review, approve, or reject with full audit traceability.
* **Disaster Recovery & Telemetry:** Features real-time Chart.js traffic analytics, DataTables forensic log inspection, interactive OpenAPI/Scalar documentation (`/scalar/v1`), and live T-SQL `.bak` backup execution.

---

## Three-Tier Role-Based Access Control (RBAC)

NexusAuth enforces both **vertical RBAC** (privilege separation between internal roles) and **horizontal RBAC** (strict multi-tenant row-level data isolation).

### 1. Administrator (Full Governance & Database Operations)
* **Global Telemetry (`Dashboard`):** Monitors system-wide active tokens, registered applications, 24-hour API traffic volume, status code distributions (`200`, `401`, `403`), and global security events.
* **Identity & Access Management (`User Management`):** Creates user accounts, assigns roles (`Administrator`, `Developer`, `Customer`), and unlocks accounts triggered by brute-force protection.
* **Unrestricted Application & Token Control (`API Tokens`):** Registers applications across `Production`, `Staging`, and `Development`, issues multi-scope keys (`read:data,write:data`), manages IP allowlists, and revokes/rotates any key.
* **Quota Governance (`Quota Requests`):** Reviews, approves, or rejects subscriber requests for higher rate limits or expanded active token ceilings.
* **Forensic Auditing (`Audit Logs`):** Inspects the complete, immutable chronological record of system changes and JSON state diffs.
* **Database Administration (`Database Admin`):** Views SQL Server storage metrics and generates point-in-time `.bak` database backups.

### 2. Developer (Internal Engineering & Integration)
* **Engineering Telemetry (`Dashboard` & `Audit Logs`):** Monitors global gateway traffic, latency (`ExecutionTimeMs`), and audit events to troubleshoot service integrations.
* **Internal Service Provisioning (`API Tokens`):** Registers internal applications, mints high-throughput read/write API keys (`1,000 req/min`), configures IP allowlists, and performs atomic key rotations.
* **Interactive API Testing (`/scalar/v1`):** Tests authenticated `GET` and `POST` requests against protected `/api/v1/DataGateway/resources` endpoints.
* **Enforced Boundaries:** Blocked from `User Management` and `Database Admin` (`403 Access Denied`).

### 3. Customer (Multi-Tenant External API Subscriber)
* **Tenant-Isolated Telemetry (`Dashboard`):** Row-level filtering (`OwnerUserId == CurrentUserId`) restricts visibility strictly to the Customer's own applications, tokens, and traffic metrics.
* **Self-Service Guardrailed Token Management (`API Tokens`):**
  * Registers client applications and generates self-service keys with optional IP allowlists.
  * Subject to automated server-side tier guardrails: **read-only scope lock (`read:data`)**, **rate-limit ceiling (`100 req/min`)**, and **active token limit (default `2` active tokens)**.
  * Can revoke or atomically rotate their own tokens while server-side ownership checks block any Insecure Direct Object Reference (IDOR) tampering against other tenants.
* **Self-Service Tier Expansion (`Quota Requests`):** Submits business/technical justifications to request higher per-token rate limits or additional active token slots.
* **Restricted Portal Surface:** Internal navigation (`Audit Logs`, `User Management`, `Database Admin`) is hidden from the UI and hard-blocked at the controller level (`403 Access Denied`).

---

## Technology Stack

* **Backend Framework:** ASP.NET Core MVC (.NET 8 / C#)
* **Database Engine:** Microsoft SQL Server with Entity Framework Core
* **Authentication & Cryptography:** Cookie Authentication, BCrypt.Net, System.Security.Cryptography (SHA-256)
* **API Documentation & Testing:** OpenAPI + Scalar UI (`/scalar/v1`)
* **Frontend & Visualization:** Razor Views, Bootstrap 5 (Dark Theme), Chart.js, jQuery DataTables

---

## Database Schema Overview

| Table | Purpose & Key Security Controls |
| :--- | :--- |
| **`Users`** | Stores user credentials (`PasswordHash`), account status, `MaxActiveTokens` ceiling, `FailedLoginAttempts` (`CHECK >= 0`), and `LockoutEnd`. |
| **`Roles` & `UserRoles`** | Defines the three-tier RBAC hierarchy (`Administrator`, `Developer`, `Customer`) via composite primary key mapping. |
| **`Applications`** | Registers client applications tied to an `OwnerUserId` foreign key for multi-tenant isolation. |
| **`ApiTokens`** | Stores `KeyPrefix`, unique SHA-256 `TokenHash`, `AllowedScopes`, `RateLimitPerMinute` (`CHECK > 0`), `AllowedIpAddresses`, and revocation timestamps. |
| **`TokenUsageLogs`** | Captures every gateway API call (`RequestedEndpoint`, `HttpMethod`, `ResponseStatusCode`, `ClientIp`, `ExecutionTimeMs`, `Timestamp`). |
| **`AuditLogs`** | Append-only compliance ledger (`DENY UPDATE, DELETE`) storing `ActionType`, `TargetEntity`, `OldValuesJson`, `NewValuesJson`, and `ClientIp`. |
| **`QuotaRequests`** | Tracks subscriber upgrade workflows (`RateLimitUpgrade` / `TokenSlotIncrease`), approval status (`Pending` / `Approved` / `Rejected`), and reviewer notes. |

---

## Getting Started

1. **Configure Database Connection:** Update `ConnectionStrings:DefaultConnection` in `appsettings.json` to point to your SQL Server instance (`NexusAuthDB`).
2. **Initialize Schema & Security Controls:** Execute the schema creation script, `sp_RotateApiToken` stored procedure, and `DENY UPDATE, DELETE ON AuditLogs` permissions in SQL Server Management Studio (SSMS).
3. **Run the Application:** Launch via Visual Studio (`F5`) or `dotnet run`, sign in with an Administrator account, and access `/scalar/v1` to test live API gateway requests.