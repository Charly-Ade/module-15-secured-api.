# Module 15: Secured Express API

Environment: Node.js 22 and Express 5

The project has 30 passing automated tests across 5 files. TypeScript and ESLint checks also pass.

## 1. Security Checklist

This checklist was created using OWASP security guidelines because the original course checklist was not available. It should be compared with the official module requirements before submission.

### Secrets and Configuration

The project does not contain hardcoded secrets. Environment variables are validated at startup, and separate access and refresh token secrets are required. Production secret management and rotation are not yet implemented.

### Authentication

Passwords are hashed using bcrypt with a cost factor of 12. Passwords are not returned in API responses. The application validates password length and uses generic login errors to reduce information leaks.

Login and registration have rate limits. However, multi factor authentication, password reset, email verification and stronger password checks are not implemented.

### Tokens

Access tokens expire after 15 minutes, while refresh tokens expire after 7 days. The application uses separate secrets, validates token signatures and rejects expired or tampered tokens.

Refresh tokens are rotated, and reuse of an old token revokes the user's newer refresh token. However, token storage is in memory, so restarting the server clears it.

### Authorization

Protected routes require authentication. Admin routes require the appropriate role, and account ownership is checked before users access accounts or transactions.

Users cannot assign themselves admin privileges or change account ownership through request bodies.

### Input Validation and Error Handling

Zod validates request bodies. Request size limits are enforced, malformed JSON is handled correctly, and internal error details are not exposed to clients.

Overdraft errors now return HTTP 422 instead of HTTP 500.

### Security Middleware

Helmet security headers, an explicit CORS allowlist and global rate limiting are configured. Authentication routes have stricter rate limits.

HTTPS must be configured when deploying the application.

### Dependencies and Testing

The project includes a package lockfile and automated security tests. No vulnerabilities were reported by npm audit.

Security event monitoring, structured logging and production secret management remain outstanding. The npm audit signatures command could not be completed because of a network error.

### OWASP Top 10

The project addresses access control, authentication, cryptographic security, input validation, security configuration and dependency vulnerabilities.

Logging and monitoring still need improvement. SQL injection and SSRF are not applicable to the current implementation because the application has no database or outbound server requests.

## 2. npm Audit Results

The following commands were run on 13 October 2026 after installing dependencies.

npm audit reported zero vulnerabilities.

npm audit --omit=dev also reported zero vulnerabilities.

The project uses established libraries, including bcrypt, jsonwebtoken, Helmet, CORS and express-rate-limit.

These results should be checked again before deployment because new security advisories may be published.

## 3. Google OAuth

Google OAuth has not been implemented because real credentials were unavailable for testing.

The application is prepared for future integration through a central token creation service. Implementation should include CSRF protection, verified email checks, secure account linking and safe token delivery.

## 4. Changes from Module 14

The following improvements were made:

1. Added registration, login, refresh and logout endpoints.
2. Added JWT authentication and bcrypt password hashing.
3. Added admin routes and role-based access control.
4. Added account ownership checks for accounts and transactions.
5. Added Zod request validation and improved error handling.
6. Added Helmet, CORS restrictions and rate limiting.
7. Added automated security tests.
8. Updated environment configuration to use separate access and refresh secrets.
9. Updated API routes to use the `/api` prefix.
10. Removed stale compiled files from the source directory.

## 5. Known Limitations

The application stores users, accounts and refresh tokens in memory. All data is lost when the server restarts.

Google OAuth, MFA, password recovery, email verification, production secret management, HTTPS configuration and security monitoring remain incomplete.

The project is suitable for further development and testing, but these limitations should be addressed before production deployment.