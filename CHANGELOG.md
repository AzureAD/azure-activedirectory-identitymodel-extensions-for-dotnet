<a name="5.0.0"></a>
# 5.0.0 (2015-06-01)

## Bug Fixes

* **Issue 43:** Fixed the error message thrown in case of invalid nonce exception.
* **Issue 51:** `AuthenticationProtocolMessage.BuildFormPost` html is not correct.
* **Issue 103:** Fixing exception thrown in case of invalid signature of token ([c07d489fad3bd540202bf9459d30f66b9bcb9b14](https://github.com/brentschmaltz/azure-activedirectory-identitymodel-extensions-for-dotnet/commit/c07d489fad3bd540202bf9459d30f66b9bcb9b14)).
* **Issue 122:** Mapping `roles` to `ClaimTypes.Role` ([PR 139](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/139)).
* **Issue 135:** `OpenIdConnectMessage.CreateAuthenticationRequestUrl` and `CreateLogoutRequestUrl` are made virtual ([PR 141](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/141)). 
* **Issue 149:** Renaming the tests folder to "test" so that build tools can find and run the tests.([PR 148](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/148)).


## Features
* **JsonWebKey:** Upgraded to support http://tools.ietf.org/html/draft-ietf-jose-json-web-key-37
* **Logging:** Added Event Source based logging in Wilson. `IdentityModelEventSource` is the exposed event source handle.

## Breaking Changes
* `TokenValidationPrameters` no longer supports SigningTokens, only SigningKeys.
*  Taking a dependency on NewtonSoft resulted the type of the `Claim.Property[JwtSecurityTokenHandler.JsonClaimTypeProperty]` to change from `typeof(IDictionary<string, object>).ToString()` to `Newtonsoft.Json.Linq.JProperty`
*  `SecurityTokenDescriptor` has been removed.
*  `TokenValidationParameters.CertificateValidator` has been removed.
*  `TokenValidationParameters.ClientDecryptionTokens` type has been changed from `ReadOnlyCollection<SecurityToken>` to `IList<SecurityToken>`.
*  `TokenValidationParameters.IssuerSigningToken` and `IssuerSigningTokens` have been removed.
*  `AsymmetricAlgorithm` has been replaced with `SignatureProvider`.
*  `X509AsymmetricSecurityKey` has been replaced with `X509SecurityKey`.
*  `SecurityKeyIdentifier` and `SecurityKeyIdentifierClause` have been dropped from the OM.
*  `SecurityKeyIdentifier` and `SecurityKeyIdentifierClause` have been dropped from the OM.
*  `JsonWebKey.KeyOps` OM change from `string` to `IList<string>` as per specifications.
*  `JsonWebKeySet.GetSigningTokens()` has been replaced by `JsonWebKeySet.GetSigningKeys()`.
*  `Microsoft.IdentityModel.Extensions.SecurityTokenHandlerCollectionExtensions` has been removed.
*  `OpenIdConnectConfiguration.SigningTokens` has been replaced by `OpenIdConnectConfiguration.SigningKeys`.
*  `OpenIdConnectProtocolException.OpenIdConnectProtocolException(SerializationInfo info, StreamingContext context)` has been removed.
*  `OpenIdConnectProtocolInvalidCHashException.OpenIdConnectProtocolInvalidCHashException(SerializationInfo info, StreamingContext context)` has been removed.
*  `OpenIdConnectProtocolInvalidNonceException.OpenIdConnectProtocolInvalidNonceException(SerializationInfo info, StreamingContext context)` has been removed.

**NOTE**: We have not added full support for WsFederation in 5.0.0 yet. Following classes are not in the new version yet:
* WsFederationConfiguration
* WsFederationConfigurationRetriever
* WsFederationMessage

**NOTE**: Saml support has been moved from `Microsoft.IdentityModel.Tokens` to `System.IdentityModel.Tokens`. Following classes were moved:
* Saml2SecurityTokenHandler
* SamlConstants
* SamlSecurityTokenHandler

** System.IdentityModel.Tokens**
* `ErrorMessages` class has been moved from Microsoft.IdentityModel.Tokens to System.IdentityModel.Tokens.
* `JwtHeader` constructor: `JwtHeadet(SigningCredentials signingCredentials)` does not assign a default null value to `signingCredentials` if not passed.
* `JwtHeader.SigningKeyIdentifier` has been removed.
* Added properties `string Kid` and `string X5t` to `JwtHeader` class.
* Added properties `DateTime ValidFrom` and `DateTime ValidTo` to `JwtPayload` class.
* `JwtSecurityToken.SigningToken` has been removed, users should use `JwtSecurityToken.SigningKey`.
* `JwtSecurityToken.SecurityKeys` has been replaced by `JwtSecurityToken.SecurityKey`. The token now contains a single key.
* In `JwtSecurityTOken`, `ResolveIssuerSigningKey(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)` has been replaced by `ResolveIssuerSigningKey(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)`
* `SecurityTokenInvalidAudienceException.SecurityTokenInvalidAudienceException(SerializationInfo info, StreamingContext context)` has been removed.
* `SecurityTokenInvalidIssuerException.SecurityTokenInvalidIssuerException(SerializationInfo info, StreamingContext context)` has been removed.
* `SecurityTokenInvalidLifetimeException.SecurityTokenInvalidLifetimeException(SerializationInfo info, StreamingContext context)` has been removed.
* Following APIs are removed from `JwtSecurityTokenHandler`:
    * public override bool CanReadToken(XmlReader reader)
    * public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
    * public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
    * public override string[] GetTokenTypeIdentifiers()
    * public override void LoadCustomConfiguration(XmlNodeList nodelist)
    * public override SecurityToken ReadToken(XmlReader reader)
    * public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
    * public override void WriteToken(XmlWriter writer, SecurityToken token)
* Classes Removed:
    * `public class NamedKeyIssuerTokenResolver`
    * `public class NamedKeySecurityKeyIdentifierClause`
    * `public class NamedKeySecurityToken`
* Classes Added:
    * `public class RSACryptoServiceProviderProxy`
    * `public class RsaSecurityKey`
    * `public static class SecurityAlgorithms`
    * `public abstract class SecurityKey`
    * `public abstract class SecurityToken`
    * `public class SecurityTokenException`
    * `public class SecurityTokenExpiredException`
    * `public abstract class SecurityTokenHandler`
    * `public class SecurityTokenInvalidSignatureException`
    * `public class SecurityTokenNotYetValidException`
    * `public class SecurityTokenReplayDetectedException`
    * `public class SecurityTokenValidationException`
    * `public class SigningCredentials`
    * `public class SymmetricSecurityKey`


