# Implementation Plan for MFA and Centralized Logging & Auditability

## Backend Changes

### MFA Implementation
- [x] Add TOTP library dependency (e.g., Google Authenticator compatible)
- [x] Modify Identity.java to include MFA secret field
- [x] Add save method to PhoenixIAMRepository.java for Identity
- [x] Modify AuthenticationEndpoint.java for MFA step after password authentication
- [x] Add JSON API endpoints in AuthenticationEndpoint.java for /api/login, /api/mfa/setup, /api/mfa/enable, /api/mfa/verify
- [x] Create MFA setup endpoint
- [x] Create MFA verification endpoint

### Centralized Logging & Auditability
- [x] Implement SLF4J/Logback for centralized logging
- [x] Create AuditLog.java entity
- [x] Create AuditLogRepository.java
- [x] Update AuthenticationEndpoint.java to log auth events
- [x] Add audit logging to TokenEndpoint.java, JWKEndpoint.java, PushWebSocketEndpoint.java
- [x] Add /api/audit/logs endpoint to fetch audit logs
- [x] Update DB schema for MFA and AuditLog tables

## Frontend Changes

### MFA Integration
- [x] Update Auth.tsx for MFA during login flow (add login form with username/password and MFA code input)
- [x] Add MFA setup page component (MfaSetup.tsx)
- [x] Update AuthContext.tsx to handle API calls for login and MFA
- [x] Integrate MFA verification in oauth2Client.ts

## Compilation Fixes
- [x] Parameterize RootEntity<ID> with abstract ID getId()
- [x] Update SimplePKEntity<T> to extend RootEntity<T>
- [x] Update CompoundPKEntity to extend RootEntity<CompoundPK>
- [x] Change GenericDAO to interface with methods: save, edit, delete, findById, getEntityClass
- [x] Remove "implements GenericDAO<E,ID>" from AuthorizationDecorator
- [x] Make Permission static in AuthorizationDecorator
- [x] Add import for Digits in MfaUtility
- [x] Fix array/List issue in AuthenticationEndpoint

## Testing and Followup
- [ ] Test MFA flow end-to-end
- [ ] Test centralized logging
- [ ] Update documentation if needed
- [x] Recompile project after compilation fixes
