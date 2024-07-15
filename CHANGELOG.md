See the [releases](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/releases) for details on bug fixes and added features.

6.36.0
======
### New feature
- A derived `ClaimsIdentity` where claim retrieval is case-sensitive. The current `ClaimsIdentity`, in .NET, retrieves claims in a case-insensitive manner which is different than querying the underlying `SecurityToken`. The new `CaseSensitiveClaimsIdentity` class provides consistent retrieval logic with `SecurityToken`. Opt in to the new behavior via an AppContext switch. See PR [#2710](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2710) for details.

### Fundamentals
- Update signing info for NuGet packages. See PR [#2696](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2696) for details.

6.35.1
======
### Bug Fix
- Remove dependency on `AadIssuerValidator.GetTenantIdFromToken` in `ValidateIssuerSigningKey`, to only consider the `tid`. An AppContext switch enables fallbacking to the previous behavior, which should not be needed. See PR [#2680](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2680) for details.

6.35.0
======
### Bug Fix
- fix `AadIssuerValidator`'s handling of trailing forward slashes. See issue [#2415] for more details.

### Feature
- Adds an AppContext switch to control HMAC key size verification. See #2421 for more details.

6.34.0
======
### Security fixes
- See https://aka.ms/IdentityModel/Jan2024/zip and https://aka.ms/IdentityModel/Jan2024/jku for details.

6.33.0
=======
## Bug Fixes:
- Clean up log messages. See [#2339](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2339) for details.

- Decouple JsonElements from JsonDocument, which causes issues in multi-threaded environments. See [#2340](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2340) for details.
6.32.3
=======
## Bug fixes:
- Fix logging messages. See [#2288](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2288) for details.
  
6.32.2
=======
## Bug fixes:
- Underlying JsonDocument is never disposed, causing high latency in large scale services. See [#2258](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2258) for details.

6.32.1
=======
## Bug fixes:
- Fix thread safety for `JsonClaimSet` Claims and `JsonWebToken` Audiences. See [#2185](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2185) for details.

6.32.0
=======
## New features:
- Adding an AAD specific signing key issuer validator. See issue [#2134](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/2134) for details.
- Better support for WsFederation. See [PR](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2100) for details.

## Bug fixes
- Address perf regression introduced in 6.31.0. See [PR](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2131) for details.

6.31.0
========
This release contains work from the following PRs and commits:

- Introduce ConfigurationValidationException(#2076)
- Disarm security artifacts(#2064)
- Throw SecurityTokenMalformedTokenException on malformed tokens(#2080)
- Add ClaimsMapping to [JsonWebTokenHandler](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/8e7f07e859629a850e375518fcce2b6057380721)

6.30.1
=========
This release contains work from the following PRs:
- Modified token validation to be async throughout the call graph #2075 
- Enforce key sizes when creating HMAC #2072
- Fix AotCompatibilityTests #2066
- Use up-to-date "now", in case take long time to get Metadata #2063

This release addresses #1743 and, as such, going forward if the SymmetricKey is smaller than the required size for HMAC IdentityModel will throw an ArgumentOutOfRangeException which is the same exception when the SymmetricKey is smaller than the minimum key size for encryption.

6.30.0
=========
Beginning in release [6.28.0](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/releases/tag/6.28.0) the library stopped throwing SecurityTokenUnableToValidateException. This version (6.30.0) marks the exception type as obsolete to make this change more discoverable. Not including it in the release notes explicitly for 6.28.0 was a mistake. This exception type will be removed completely in the next few months as the team moves towards a major version bump. More information on how to replace the usage going forward can be found here: https://aka.ms/SecurityTokenUnableToValidateException

Indicate that a SecurityTokenDescriptor can create JWS or JWE
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2055
Specify 'UTC' in log messages
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/ceb10b10ad2edb97217e263915d407da1d957e03
Fix order of log messages
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/05eeeb513e66a4236ae519ef9304bf2b6f26766f

Fixed issues with matching Jwt.Kid with a X509SecurityKey.x5t
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2057
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2061

Marked Exception that is no longer used as obsolete
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2060

Added support for AesGcm on .NET 6.0 or higher
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/85fa86af743e2b1a0078a9ecd956f34ee703acfc

First round of triming analysis preperation for AOT
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2042

Added new API on TokenHandler.ValidateTokenAsync(SecurityToken ...) implemented only on JsonWebTokenHandler.
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2056

6.29.0
=========
- Add BootstrapRefreshInterval (#2052)
- Added net462 target (#2049)
- Create the configuration cache in the BaseConfigurationManager class (#2048)

6.28.1
=========
- Add BootstrapRefreshInterval (#2052)
- Added net462 target (#2049)
- Create the configuration cache in the BaseConfigurationManager class (#2048)

6.28.0
========
* Update Wilson logs with aka.ms pointers to known wikis in https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2027
* Fix typo in documentation https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2034
* Introduce a LKG configuration cache to store each valid base configuration instead of a single entry of configuration https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2007
* Add encryption keys to base configuration https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2023
* Updated CHANGELOG link https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2026

6.27.0
========
Servicing release
Set maximum depth for Newtonsoft parsing.
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2024
Improve metadata failure message.
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2010
Validate size of symmetric signatures.
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/2008
Added property TokenEndpoint to BaseConfiguration.
https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/1998

6.26.1
=========
### Bug Fixes:

Releasing a Hotfix for Wilson 6.26.0 that reverts async/await changes made in #1996 to address a performance reduction issue.
- Changes are in #2015
- Root cause analysis and fix will be tracked in #2017


Next release (6.22.1 or 6.23.0)
=========
### New Features:
Microsoft.IdentityModel has two assemblies to manipulate JWT tokens:

System.IdentityModel.Tokens.Jwt, which is the legacy assembly. It defines JwtSecurityTokenHandler class to manipulate JWT tokens.
Microsoft.IdentityModel.JsonWebTokens, which defines the JsonWebToken class and JsonWebTokenHandler, more modern, and more efficient.
When using JwtSecurityTokenHandler, the short named claims (oid, tid), used to be transformed into the long named claims (with a namespace). With JsonWebTokenHandler this is no longer the case, but when you migrate your application from using JwtSecurityTokenHandler to JsonWebTokenHandler (or use a framework that does), you will only get original claims sent by the IdP. This is more efficient, and occupies less space, but might trigger a lot of changes in your application. In order to make it easier for people to migrate without changing their app too much, this PR offers extensibility to re-add the claims mapping.

### Bug Fixes:


6.22.0
=========

### New Features:

**Unmasked non-PII properties in log messages -**
In Microsoft.IdentityModel logs, previously only system metadata (DateTime, class name, httpmethod etc.) was displayed in clear text. For all other log arguments, the type was being logged to prevent Personally Identifiable Information (PII) from being displayed when ShowPII flag is turned OFF. To improve troubleshooting experience non-PII properties - Issuer, Audience, Key location, Key Id (kid) and some SAML constants will now be displayed in clear text. See issue #1903 for more details.

**Prefix Wilson header message to the first log message -**
To always log the Wilson header (Version, DateTime, PII ON/OFF message), EventLogLevel.LogAlways was mapped to LogLevel.Critical in Microsoft.IdentityModel.LoggingExtensions.IdentityLoggerAdapter class which caused confusion on why header was being displayed as a fatal log.
To address this, header is now prefixed to the first message logged by Wilson and separated with a newline. EventLogLevel.LogAlways has been remapped to LogLevel.Trace. See issue #1907 for more details.

### Bug Fixes:

**[Copy the IssuerSigningKeyResolverUsingConfiguration delegate in Clone()](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/652d5d8d7371c2882306d3e95fc6e0de21ac7411)** #1909
