# WebSphere Application Server SMF Audit Field Mapping

## Overview

WebSphere Application Server on z/OS includes an SMF emitter that serves as a bridge between the WebSphere audit framework and the z/OS System Management Facilities (SMF). SMF is IBM's mainframe logging and monitoring facility that captures system and application activity for auditing purposes.

When security-related events occur in WebSphere Application Server, the audit framework captures these events and the SMF emitter converts them into SMF records that can be processed by standard z/OS reporting tools.

## SMF Record Structure

SMF records created by WebSphere have the following characteristics:

- **Record Type**: A specific SMF record type for WebSphere Application Server
- **Subtype**: Set to 5
- **Component Name**: "WASAUDITCOMP"
- **FMID**: "H28W700"
- **Event Code**: Mapped from WebSphere event types
- **Event Qualifier**: Set based on outcome (0-6)

## WebSphere to SMF Field Mapping

The WebSphere audit fields are mapped to SMF relocate sections with specific IDs. Here's how the fields from your audit log are mapped:

| WebSphere Field | SMF Relocate Section ID | Description |
|----------------|------------------------|-------------|
| Event Type | Event Code | Maps to different SMF event codes (e.g., SECURITY_AUTHN maps to SMF_SECURITY_AUTHN_CODE) |
| Outcome | Event Success/Failure flag | Sets whether the event was successful or failed |
| OutcomeReason | 163 | The reason for the outcome |
| OutcomeReasonCode | 164 | Numeric code for the outcome reason |
| SessionId | 105 | HTTP session ID |
| RemoteHost | 108 | Hostname of the client |
| RemoteAddr | 106 | IP address of the client |
| RemotePort | 107 | Port number on the client |
| ProgName | 110 | Program or resource being accessed |
| Action | 111 | Type of action being performed |
| AppUserName | 113 | Application username |
| ResourceName (NAME_IN_APP) | 115 | Name of the resource being accessed |
| RegistryUserName | 112 | Username in the registry |
| AccessDecision | 114 | Result of access control decision |
| ResourceType | 116 | Type of resource being accessed |
| ResourceUniqueId | 117 | Unique identifier for the resource |
| PermissionsChecked | 118 | Permissions checked during authorization |
| PermissionsGranted | 119 | Permissions granted during authorization |
| RolesChecked | 120 | Roles checked during authorization |
| RolesGranted | 121 | Roles granted during authorization |
| CreationTime | 102 | Timestamp of event creation |
| GlobalInstanceId | 103 | Globally unique identifier for the event |
| LastEventTrailId | 100 | ID of previous event in trail |
| EventTrailId | 101 | ID of current event trail |
| FirstCaller | 123 | First caller in call chain |
| CallerList | 124 | List of callers in call chain |
| Domain | 126 | Security domain |
| Realm | 127 | Security realm |
| RegistryType | 129 | Type of user registry |
| AuthnType | 135 | Authentication mechanism type |
| Provider | 137 | Authentication provider |
| ProviderStatus | 138 | Status of authentication provider |

## Special Field Handling

1. **Sequence Number**: Added to every record (relocate section 162)

2. **Field Truncation**: If a record exceeds the SMF size limit, fields are truncated to a configurable length (default is 256 bytes) and HTTP headers and custom data may be omitted

3. **Event-Specific Fields**: Depending on the event type, additional fields are included:
   - Authentication events: AuthnType (135)
   - Authentication delegation events: DelegationType (131), RoleName (132), IdentityName (133)
   - Authentication mapping events: MappedSecurityDomain (140), MappedRealm (141), MappedUserName (142)
   - Authentication termination events: TerminateReason (144)
   - Policy-related events: PolicyName (146), PolicyType (147)
   - Key-related events: KeyLabel (149), KeyLocation (150), CertLifetime (151)
   - Management events: MgmtType (153), MgmtCommand (154), TargetInfoAttributes (155)
   - Resource access events: URL (157), HTTP headers (158, 159)

4. **Custom Properties**: Added as relocate section 161 if present and if the record isn't too large

## SMF Event Type Codes

WebSphere event types are mapped to specific SMF event codes:

| WebSphere Event Type | SMF Event Code Value |
|---------------------|---------------------|
| SECURITY_AUTHN | 1 |
| SECURITY_AUTHN_TERMINATE | 2 |
| SECURITY_AUTHN_MAPPING | 3 |
| SECURITY_AUTHZ | 4 |
| SECURITY_MGMT_POLICY | 5 |
| SECURITY_MGMT_REGISTRY | 6 |
| SECURITY_RUNTIME | 7 |
| SECURITY_MGMT_CONFIG | 8 |
| SECURITY_MGMT_PROVISIONING | 9 |
| SECURITY_MGMT_RESOURCE | 10 |
| SECURITY_RUNTIME_KEY | 11 |
| SECURITY_MGMT_KEY | 12 |
| SECURITY_MGMT_AUDIT | 13 |
| SECURITY_RESOURCE_ACCESS | 14 |
| SECURITY_SIGNING | 15 |
| SECURITY_ENCRYPTION | 16 |
| SECURITY_AUTHN_DELEGATION | 17 |
| SECURITY_AUTHN_CREDS_MODIFY | 18 |
| ADMIN_REPOSITORY_SAVE | 19 |
| SECURITY_FORM_LOGIN | 20 |
| SECURITY_FORM_LOGOUT | 21 |
| SECURITY_SPNEGO_LOGIN | 22 |
| SECURITY_SPNEGO_LOGOUT | 23 |
| SECURITY_KERBEROS_LOGIN | 24 |
| SECURITY_KERBEROS_LOGOUT | 25 |

## Outcome Qualifiers

The outcome of an event is mapped to a qualifier value:

| Outcome | Qualifier Value |
|---------|----------------|
| S_SUCCESS | 0 |
| S_INFO | 1 |
| S_WARNING | 2 |
| S_FAILURE | 3 |
| S_REDIRECT | 4 |
| S_DENIED | 5 |
| S_ERROR | 6 |

## Summary

WebSphere Application Server on z/OS provides integration with the System Management Facilities (SMF) through a specialized emitter component. This integration allows WebSphere security events to be recorded in the standard z/OS audit repository, enabling:

1. Consolidated security monitoring across z/OS applications
2. Integration with existing mainframe security tools and processes
3. Standardized reporting of security events
4. Compliance with enterprise audit requirements

The SMF records contain detailed information about security events, including authentication attempts, authorization decisions, and administrative actions, allowing security administrators to monitor and report on WebSphere security activities using standard z/OS tools.