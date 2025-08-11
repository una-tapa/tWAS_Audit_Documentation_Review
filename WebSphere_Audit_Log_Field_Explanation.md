# WebSphere Audit Log Field Explanation

This document provides a comprehensive explanation of all audit event fields in WebSphere Application Server security audit logs. These fields are defined in the `SecurityAuditEventImpl.java` class and are used to record security-related events.

## Table of Contents
- [Event Identification Fields](#event-identification-fields)
- [Outcome Information](#outcome-information)
- [Session Information](#session-information)
- [Authentication Information](#authentication-information)
- [User Identity Information](#user-identity-information)
- [Process and Domain Information](#process-and-domain-information)
- [Resource Access Information](#resource-access-information)
- [Authorization Information](#authorization-information)
- [Delegation Information](#delegation-information)
- [Authentication Mapping Information](#authentication-mapping-information)
- [Provider Information](#provider-information)
- [Policy Information](#policy-information)
- [Key and Certificate Information](#key-and-certificate-information)
- [Management Information](#management-information)
- [HTTP Information](#http-information)
- [Event Trail Information](#event-trail-information)
- [Detailed Field Explanations](#detailed-field-explanations)
  - [Event Type Values](#event-type-values)
  - [Outcome Values](#outcome-values)
  - [Outcome Reason Codes](#outcome-reason-codes)
  - [Remote Address and Host Information](#remote-address-and-host-information)
  - [Authentication Types](#authentication-types)
  - [Caller Information](#caller-information)
  - [Registry Types](#registry-types)
  - [Action Types](#action-types)
  - [Resource Types](#resource-types)
  - [Access Decisions](#access-decisions)
  - [Delegation Types](#delegation-types)
  - [Provider Status Values](#provider-status-values)
  - [Policy Types](#policy-types)
  - [Management Types and Commands](#management-types-and-commands)
- [Example Audit Log Entry](#example-audit-log-entry)

## Event Identification Fields

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_seq`](#event-identification-fields) | Integer | Sequence number of the event, used to track the order of audit events | Numeric values starting from 0 |
| [`_eventType`](#event-type-values) | String | Type of security event | See [Event Type Values](#event-type-values) |
| [`_globalInstanceId`](#event-identification-fields) | Long | Globally unique identifier for the event instance | Numeric value |

## Outcome Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_outcome`](#outcome-values) | String | Result of the security event | See [Outcome Values](#outcome-values) |
| [`_outcomeReason`](#outcome-values) | String | Reason for the outcome | Various text descriptions explaining the outcome, especially for failures |
| [`_outcomeReasonCode`](#outcome-reason-codes) | long | Numeric code representing the outcome reason | See [Outcome Reason Codes](#outcome-reason-codes) |

## Session Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_sessionId`](#session-information) | String | Identifier for the user's session | Session ID string |
| [`_remoteAddr`](#remote-address-and-host-information) | String | IP address of the client that initiated the request | IP address in standard format |
| [`_remotePort`](#remote-address-and-host-information) | String | Port number used by the client | Numeric port value as string |
| [`_remoteHost`](#remote-address-and-host-information) | String | Hostname of the client that initiated the request | Hostname string |

## Authentication Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_authnType`](#authentication-types) | String | Type of authentication used | See [Authentication Types](#authentication-types) |
| [`_terminateReason`](#authentication-information) | String | Reason for authentication termination | Text description of why authentication was terminated |

## User Identity Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_registryUserName`](#user-identity-information) | String | Username as stored in the user registry | Username string |
| [`_appUserName`](#user-identity-information) | String | Username as known to the application | Username string |
| [`_firstCaller`](#caller-information) | String | First caller in the call chain | Username or identifier string |
| [`_callerList`](#caller-information) | String[] | List of all callers in the propagation chain | Array of username or identifier strings |
| [`_identityName`](#user-identity-information) | String | Name of the identity being used | Identity name string |

## Process and Domain Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_domain`](#process-and-domain-information) | String | Security domain where the event occurred | Domain name string |
| [`_realm`](#process-and-domain-information) | String | Security realm where the event occurred | Realm name string |
| [`_registryType`](#registry-types) | String | Type of user registry being used | See [Registry Types](#registry-types) |

## Resource Access Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_progName`](#resource-access-information) | String | Name of the program or application | Program or application name |
| [`_action`](#action-types) | String | Action being performed | See [Action Types](#action-types) |
| [`_accessDecision`](#access-decisions) | String | Decision made about the access request | See [Access Decisions](#access-decisions) |
| [`_resourceName`](#resource-access-information) | String | Name of the resource being accessed | Resource name string |
| [`_resourceType`](#resource-types) | String | Type of resource being accessed | See [Resource Types](#resource-types) |
| [`_resourceUniqueId`](#resource-access-information) | Long | Unique identifier for the resource | Numeric ID |
| [`_url`](#resource-access-information) | String | URL being accessed (for web resources) | URL string |

## Authorization Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_permissionsChecked`](#authorization-information) | String[] | List of permissions that were checked | Array of permission strings |
| [`_permissionsGranted`](#authorization-information) | String[] | List of permissions that were granted | Array of permission strings |
| [`_rolesChecked`](#authorization-information) | String[] | List of roles that were checked | Array of role name strings |
| [`_rolesGranted`](#authorization-information) | String[] | List of roles that were granted | Array of role name strings |

## Delegation Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_delegationType`](#delegation-types) | String | Type of delegation being performed | See [Delegation Types](#delegation-types) |
| [`_roleName`](#delegation-information) | String | Name of the role being delegated | Role name string |

## Authentication Mapping Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_mappedSecurityDomain`](#authentication-mapping-information) | String | Security domain to which the user is mapped | Domain name string |
| [`_mappedRealm`](#authentication-mapping-information) | String | Security realm to which the user is mapped | Realm name string |
| [`_mappedUserName`](#authentication-mapping-information) | String | Username to which the original user is mapped | Username string |

## Provider Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_provider`](#provider-information) | String | Name of the security provider | Provider name string |
| [`_providerStatus`](#provider-status-values) | String | Status of the security provider | See [Provider Status Values](#provider-status-values) |

## Policy Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_policyName`](#policy-information) | String | Name of the security policy | Policy name string |
| [`_policyType`](#policy-types) | String | Type of security policy | See [Policy Types](#policy-types) |

## Key and Certificate Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_keyLabel`](#key-and-certificate-information) | String | Label of the key being used | Key label string |
| [`_keyLocation`](#key-and-certificate-information) | String | Location of the key | Key location path |
| [`_certLifetime`](#key-and-certificate-information) | Date | Lifetime/expiration date of the certificate | Date value |

## Management Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_mgmtType`](#management-types-and-commands) | String | Type of management operation | See [Management Types and Commands](#management-types-and-commands) |
| [`_mgmtCommand`](#management-types-and-commands) | String | Management command being executed | See [Management Types and Commands](#management-types-and-commands) |
| [`_targetInfoAttributes`](#management-information) | TargetAttributes[] | Attributes of the management target | Array of target attribute objects |

## HTTP Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_httpRequestHeaders`](#http-information) | Attributes[] | Headers from the HTTP request | Array of HTTP header attribute objects |
| [`_httpResponseHeaders`](#http-information) | Headers from the HTTP response | Array of HTTP header attribute objects |

## Event Trail Information

| Field Name | Type | Description | Possible Values |
|------------|------|-------------|----------------|
| [`_lastEventTrailId`](#event-trail-information) | String | ID of the last event in the trail | Event trail ID string |
| [`_eventTrailId`](#event-trail-information) | String[] | IDs of all events in the trail | Array of event trail ID strings |
| [`_creationTime`](#event-trail-information) | Date | Time when the audit event was created | Date value |

## Detailed Field Explanations

### Event Type Values

The `_eventType` field indicates the type of security event that occurred. Possible values include:

- **SECURITY_AUTHN**: Authentication event
- **SECURITY_AUTHZ**: Authorization event
- **SECURITY_AUTHN_DELEGATION**: Authentication delegation event
- **SECURITY_AUTHN_MAPPING**: Authentication mapping event
- **SECURITY_AUTHN_TERMINATE**: Authentication termination event
- **SECURITY_ENCRYPTION**: Encryption operation event
- **SECURITY_MGMT_AUDIT**: Audit management event
- **SECURITY_MGMT_CONFIG**: Configuration management event
- **SECURITY_MGMT_KEY**: Key management event
- **SECURITY_MGMT_POLICY**: Policy management event
- **SECURITY_MGMT_PROVISIONING**: Provisioning management event
- **SECURITY_MGMT_REGISTRY**: Registry management event
- **SECURITY_MGMT_RESOURCE**: Resource management event
- **SECURITY_RESOURCE_ACCESS**: Resource access event
- **SECURITY_RUNTIME**: Security runtime event
- **SECURITY_RUNTIME_KEY**: Runtime key event
- **SECURITY_SIGNING**: Signing operation event
- **ADMIN_REPOSITORY_SAVE**: Admin repository save event
- **SECURITY_FORM_LOGIN**: Form-based login event
- **SECURITY_FORM_LOGOUT**: Form-based logout event
- **SECURITY_SPNEGO_LOGIN**: SPNEGO login event
- **SECURITY_SPNEGO_LOGOUT**: SPNEGO logout event
- **SECURITY_KERBEROS_LOGIN**: Kerberos login event
- **SECURITY_KERBEROS_LOGOUT**: Kerberos logout event

### Outcome Values

The `_outcome` field indicates the result of the security event. Common values include:

- **SUCCESS**: The operation completed successfully
- **FAILURE**: The operation failed
- **ERROR**: An error occurred during the operation
- **WARNING**: The operation completed with warnings
- **INFO**: Informational message about the operation

The `_outcomeReason` field provides a human-readable description of why the outcome occurred, especially useful for failures.

### Outcome Reason Codes

The `_outcomeReasonCode` field is a numeric value that provides specific information about why a security operation succeeded or failed. These codes are used in conjunction with the `_outcome` and `_outcomeReason` fields to give detailed information about the result of security events.

#### Authentication-Related Outcomes

Authentication events (`SECURITY_AUTHN`, `SECURITY_FORM_LOGIN`, etc.) may have these outcomes:
- "authnSuccess" - Authentication was successful
- "authnRedirect" - Authentication resulted in a redirect
- "authnFailure" - Authentication failed
- "mappingSuccess" - User mapping was successful

#### Authorization-Related Outcomes

Authorization events (`SECURITY_AUTHZ`) may have these outcomes:
- "authzSuccess" - Authorization was successful
- "authzDenied" - Authorization was denied
- "accessSuccess" - Access was granted
- "accessRedirect" - Access resulted in a redirect

#### Common Outcome Reason Codes

While the specific numeric values for outcome reason codes are not explicitly defined in the AuditConstants.java file, the following categories of reason codes are commonly used:

1. **Authentication Failures**
   - Invalid credentials
   - Account locked
   - Password expired
   - Certificate validation failure

2. **Authorization Failures**
   - Insufficient permissions
   - Role validation failure
   - Resource access denied
   - Policy evaluation failure

3. **Runtime Issues**
   - Session timeout
   - Token validation failure
   - Context propagation failure
   - Delegation failure

4. **Configuration Problems**
   - Missing security configuration
   - Invalid security settings
   - Registry unavailable
   - Provider failure

### Remote Address and Host Information

The `_remoteAddr`, `_remoteHost`, and `_remotePort` fields provide information about the client that initiated the request:

- `_remoteAddr`: The IP address of the client, obtained directly from `HttpServletRequest.getRemoteAddr()`
- `_remoteHost`: The hostname of the client, obtained from `HttpServletRequest.getRemoteHost()` when hostname lookup is enabled
- `_remotePort`: The port number used by the client, obtained from `HttpServletRequest.getRemotePort()`

There's a performance optimization where hostname lookup can be disabled using the `SecurityConfig.INCLUDE_HOSTNAME_IN_AUDIT` property. When set to "false", `_remoteHost` is set to null to avoid the potentially expensive DNS lookup.

### Authentication Types

The `_authnType` field indicates the type of authentication mechanism used. Possible values include:

- **challengeResponse**: Standard challenge-response authentication
- **returnResponse**: Return-based response authentication
- **trustRelationship**: Trust-based authentication
- **transportLayer**: Transport layer security authentication
- **spnego**: SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) authentication
- **jaspiWebAuthValidateRequest**: JASPI web authentication validate request
- **jaspiWebAuthSecureResponse**: JASPI web authentication secure response

### Caller Information

The `_firstCaller` and `_callerList` fields provide information about the call chain in a security context:

- `_firstCaller`: Represents the immediate caller of the current operation
- `_callerList`: Represents the entire chain of callers in a propagation scenario

These fields are obtained from the WebSphere security context:

1. If security propagation is not enabled:
   - `_firstCaller` is the name of the first principal in the current subject
   - `_callerList` contains duplicated entries of the same caller

2. If security propagation is enabled:
   - `_firstCaller` comes from `WSSecurityHelper.getFirstCaller()`
   - `_callerList` comes from `WSSecurityHelper.getCallerList()` if `propagateFirstCallerOnly` is false, otherwise it's similar to the non-propagation case

### Registry Types

The `_registryType` field indicates the type of user registry used for authentication. Common values include:

- **LOCALOS**: Local operating system registry
- **LDAP**: Lightweight Directory Access Protocol registry
- **CUSTOM**: Custom registry implementation
- **FEDERATED**: Federated registry

### Action Types

The `_action` field indicates the type of action being performed. Possible values include:

- **create**: Create a resource
- **delete**: Delete a resource
- **modify**: Modify a resource
- **show**: View a resource
- **associate**: Associate resources
- **disassociate**: Disassociate resources
- **passthru**: Pass through to another system
- **retrieve**: Retrieve a resource
- **markTrusted**: Mark a resource as trusted
- **markUntrusted**: Mark a resource as untrusted
- **register**: Register a resource
- **enable**: Enable a resource
- **disable**: Disable a resource
- **checkAccess**: Check access to a resource
- **validate**: Validate a resource
- **suspend**: Suspend a resource
- **restore**: Restore a resource
- **retire**: Retire a resource
- **transfer**: Transfer a resource
- **delegate**: Delegate access
- **passwordChange**: Change a password
- **passwordPickUp**: Pick up a password
- **changePolicyEnforcementAction**: Change policy enforcement action
- **adopt**: Adopt a resource
- **login**: Log in
- **logout**: Log out
- **authentication**: Perform authentication
- **reauthentication**: Perform reauthentication
- **tokenReceipt**: Receive a token
- **tokenIssue**: Issue a token
- **credsRefresh**: Refresh credentials
- **encrypt**: Encrypt data
- **decrypt**: Decrypt data
- **sign**: Sign data
- **webAuth**: Web authentication

### Resource Types

The `_resourceType` field indicates the type of resource being accessed. Common values include:

- **ejb**: Enterprise JavaBean
- **web**: Web resource
- **sca**: Service Component Architecture resource
- **soap**: SOAP web service
- **j2ee**: Java EE resource
- **process**: Process resource

### Access Decisions

The `_accessDecision` field indicates the decision made about an access request. Possible values include:

- **denied**: Access was denied
- **permitted**: Access was permitted
- **permittedWarning**: Access was permitted with warnings
- **Unknown**: The decision is unknown
- **authnSuccess**: Authentication was successful
- **authzSuccess**: Authorization was successful
- **authzDenied**: Authorization was denied

### Delegation Types

The `_delegationType` field indicates the type of delegation being performed. Possible values include:

- **switchUserDelegation**: Switch user delegation
- **runAsDelegaton**: Run-as delegation
- **noDelegaton**: No delegation
- **simpleDelegation**: Simple delegation

### Provider Status Values

The `_providerStatus` field indicates the status of the security provider. Possible values include:

- **providerSuccess**: The provider operation was successful
- **failure**: The provider operation failed

### Policy Types

The `_policyType` field indicates the type of security policy. Possible values include:

- **acl**: Access Control List
- **protectedObjectPolicy**: Protected Object Policy
- **authzRule**: Authorization Rule
- **actionGroup**: Action Group
- **loginPolicy**: Login Policy
- **accountPolicy**: Account Policy
- **key**: Key Policy
- **provisioningPolicy**: Provisioning Policy
- **identityPolicy**: Identity Policy
- **passwordPolicy**: Password Policy
- **policy**: Generic Policy

### Management Types and Commands

The `_mgmtType` field indicates the type of management operation. Possible values include:

- **server**: Server management
- **subSystem**: Subsystem management
- **config**: Configuration management
- **notification**: Notification management
- **WASServer**: WebSphere Application Server management
- **AuditSubSystem**: Audit subsystem management
- **SecurityServer**: Security server management

The `_mgmtCommand` field indicates the specific management command being executed. Possible values include:

- **auditStart**: Start audit
- **auditStop**: Stop audit
- **auditLevelChange**: Change audit level
- **auditPolicyAdd**: Add audit policy
- **auditPolicyDelete**: Delete audit policy
- **auditPolicyModify**: Modify audit policy
- **auditNotificationPolicy**: Audit notification policy
- **auditNotificationChange**: Change audit notification
- **createKeyStore**: Create key store
- **deleteKeyStore**: Delete key store
- **addKeyStoreEntry**: Add key store entry
- **modifyKeyStoreEntry**: Modify key store entry
- **removeKeyStoreEntry**: Remove key store entry
- **createTrustStore**: Create trust store
- **deleteTrustStore**: Delete trust store
- **addTrustStoreEntry**: Add trust store entry
- **modifyTrustStoreEntry**: Modify trust store entry
- **removeTrustStoreEntry**: Remove trust store entry

## Example Audit Log Entry

```
Event Type = SECURITY_AUTHN | Outcome = SUCCESSFUL | OutcomeReason = SUCCESS | OutcomeReasonCode = 5 | SessionId = null | RemoteHost = boss0187.pok.ibm.com | RemoteAddr = 9.57.7.187 | RemotePort = 7063 | ProgName = /transfer/download/cells/WAS00Network/nodes/ndnode1/servers/server1/server.xml6173264192813327781.tmp | Action = webAuth | AppUserName = server:WAS00Network_WAS00Manager_dmgr | ResourceName = GET | RegistryUserName = BOSS0187.POK.IBM.COM/server:WAS00Network_WAS00Manager_dmgr | AccessDecision = authnSuccess | ResourceType = web | ResourceUniqueId = 0 | PermissionsChecked = null | PermissionsGranted = null | RolesChecked = null | RolesGranted = null | CreationTime = Wed Jun 18 18:53:41 GMT 2025 | GlobalInstanceId = 0 | LastEventTrailId = null | EventTrailId = null | FirstCaller = /WSGUEST | CallerList = /WSGUEST , /WSGUEST | Domain = null | Realm = BOSS0187.POK.IBM.COM | RegistryType = LOCALOS | AuthnType = challengeResponse | Provider = WebSphere | ProviderStatus = providerSuccess
```

In this example:
- The event is a successful authentication (`SECURITY_AUTHN` with `Outcome = SUCCESSFUL`)
- The outcome reason code is 5, indicating a successful authentication
- The authentication type is "challengeResponse"
- The user is authenticated against a local operating system registry (`RegistryType = LOCALOS`)
- The authentication was performed by the WebSphere security provider
- The action was "webAuth" (web authentication)
- The resource being accessed was a web resource with a GET request
- The authentication was for a server identity (`server:WAS00Network_WAS00Manager_dmgr`)