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

* **Microsoft.IdentityModel.Protocol.Extensions**
    * **Removed:**
        * `SecurityTokenHandlerCollectionExtensions` class has been removed.
        * `OpenIdConnectConfiguration.SigningTokens` has been removed.
        * `OpenIdConnectProtocolException.OpenIdConnectProtocolException(SerializationInfo info, StreamingContext context)` has been removed.
        * `OpenIdConnectProtocolInvalidCHashException.OpenIdConnectProtocolInvalidCHashException(SerializationInfo info, StreamingContext context)` has been removed.
        * `OpenIdConnectProtocolInvalidNonceException.OpenIdConnectProtocolInvalidNonceException(SerializationInfo info, StreamingContext context)` has been removed.
    * **Changed:**
        * Type of `ClientDecryptionTokens` has been changed from `ReadOnlyCollection<SecurityToken>` to `IList<SecurityToken>`.
        * `JsonWebKey.KeyOps` OM changed from `string` to `IList<string>` as per specifications.
        * `JsonWebKeySet.GetSigningTokens()` has been replaced by `JsonWebKeySet.GetSigningKeys()`.
    * **Added:**
        * `ErrorMessages` class. List of all messages that we log and/or throw.
        * `Base64UrlConverter` class has been added. It provides APIs to read and write Json objects.
        * Additional string  constants to `JsonWebKeyParameterNames`.
        * `OpenIdConnectConfiguration Create(string json)` method has been added.
* **System.IdentityModel.Tokens**
    * **Removed:**  
        * `SecurityTokenDescriptor` has been removed.
        * `SecurityKeyIdentifier` and `SecurityKeyIdentifierClause` have been dropped from the OM.
        * `JwtHeader.SigningKeyIdentifier` has been removed.
        * `JwtSecurityToken.SigningToken` has been removed, users should use `JwtSecurityToken.SigningKey`.
        * `SecurityTokenInvalidAudienceException.SecurityTokenInvalidAudienceException(SerializationInfo info, StreamingContext context)` has been removed.
        * `SecurityTokenInvalidIssuerException.SecurityTokenInvalidIssuerException(SerializationInfo info, StreamingContext context)` has been removed.
        * `SecurityTokenInvalidLifetimeException.SecurityTokenInvalidLifetimeException(SerializationInfo info, StreamingContext context)` has been removed.
        * `TokenValidationParameters`:   
            * No longer supports `SigningTokens`, only `SigningKeys`.
            * `CertificateValidator` has been removed.
            * `IssuerSigningToken` and `IssuerSigningTokens` have been removed.
        * `JwtSecurityTokenHandler`:
            * public override bool CanReadToken(XmlReader reader)
            * public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
            * public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
            * public override string[] GetTokenTypeIdentifiers()
            * public override void LoadCustomConfiguration(XmlNodeList nodelist)
            * public override SecurityToken ReadToken(XmlReader reader)
            * public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
            * public override void WriteToken(XmlWriter writer, SecurityToken token)
        * Classes Removed:
            * public class NamedKeyIssuerTokenResolver
            * public class NamedKeySecurityKeyIdentifierClause
            * public class NamedKeySecurityToken
    * **Changed:**
        * `ErrorMessages` class has been moved from Microsoft.IdentityModel.Tokens to System.IdentityModel.Tokens.
        * `JwtHeader` constructor: `JwtHeadet(SigningCredentials signingCredentials)` does not assign a default null value to `signingCredentials` if not passed.
        *  `AsymmetricAlgorithm` has been replaced with `SignatureProvider`.
        *  `X509AsymmetricSecurityKey` has been replaced with `X509SecurityKey`.
        *  `JwtSecurityToken.SecurityKeys` has been replaced by `JwtSecurityToken.SecurityKey`. The token now contains a single key
        *  `JwtSecurityTOken.ResolveIssuerSigningKey(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)` has been replaced by `ResolveIssuerSigningKey(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)`
        *  Taking a dependency on NewtonSoft resulted the type of the `Claim.Property[JwtSecurityTokenHandler.JsonClaimTypeProperty]` to change from `typeof(IDictionary<string, object>).ToString()` to `Newtonsoft.Json.Linq.JProperty`.
        *  `TokenValidationParameters.IssuerSigningKeyResolve`' method takes a `string kid` instead of `SecurityKeyIdentifier keyIdentifier` as parameter.
    *  **Added:**
        * Added properties `string Kid` and `string X5t` to `JwtHeader` class.
        * Added properties `DateTime ValidFrom` and `DateTime ValidTo` to `JwtPayload` class.
        * Classes Added:
            * public class RSACryptoServiceProviderProxy
            * public class RsaSecurityKey
            * public static class SecurityAlgorithms
            * public abstract class SecurityKey
            * public abstract class SecurityToken
            * public class SecurityTokenException
            * public class SecurityTokenExpiredException
            * public abstract class SecurityTokenHandler
            * public class SecurityTokenInvalidSignatureException
            * public class SecurityTokenNotYetValidException
            * public class SecurityTokenReplayDetectedException
            * public class SecurityTokenValidationException
            * public class SigningCredentials
            * public class SymmetricSecurityKey
            * public class SignatureVerificationFailedException
            * public class AsymmetricSecurityKey


* **NOTE:** We have not added full support for WsFederation in 5.0.0 yet. Following classes are not in the new version yet:
    * WsFederationConfiguration
    * WsFederationConfigurationRetriever
    * WsFederationMessage

* **NOTE:** Saml classes has been moved from `Microsoft.IdentityModel.Tokens` to `System.IdentityModel.Tokens`. It is not fully supported yet. Following classes were moved:
    * Saml2SecurityTokenHandler
    * SamlConstants
    * SamlSecurityTokenHandler