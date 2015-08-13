<a name="5.0.0"></a>
# 5.0.0 (2015-06-01)

## Bug Fixes

* **[Issue 43](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/43):** Fixed the error message thrown in case of invalid nonce exception.
* **[Issue 51](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/51):** `AuthenticationProtocolMessage.BuildFormPost` html is not correct.
* **[Issue 95](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/95):** Replacing the static claimType maps on `JwtSecurityTokenHandler` by instances ([PR 219](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/219)).
* **[Issue 103](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/103):** Fixing exception thrown in case of invalid signature of token ([PR 104](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/104)).
* **[Issue 122](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/122):** Mapping `roles` to `ClaimTypes.Role` ([PR 139](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/139)).
* **[Issue 135](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/135):** `OpenIdConnectMessage.CreateAuthenticationRequestUrl` and `CreateLogoutRequestUrl` are made virtual ([PR 141](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/141)). 
* **[Issue 136](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/136):** If a `JwtPayload` has a claim with null value, it will be dropped from the `ClaimsIdentity` and not throw the null exception ([PR 211](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/211)).
* **[Issue 137](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/137):** Not adding '?' delimiter if the endpoint URL already has one ([PR 207](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/207)).
* **[Issue 149](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/149):** Renaming the tests folder to "test" so that build tools can find and run the tests ([PR 148](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/148)).
* **[Issue 174](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/174):** Calling IssuerSigningKeyValidator delegate if set by the user ([PR 207](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/207)).
* **[Issue 176](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/176):** Adding `OpenIdConnectConfiguration.Write` method to serialize `OpenIdConnectConfiguration` object back to JSON ([PR 218](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/218)).
* **[Issue 183](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/183):** Fixing the "double" await causing a deadlock in `HttpDocumentRetriever.cs` ([PR 207](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/207)).
* **[Issue 201](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/201):** Adding comments to `TokenValidationParameters` to explain what each property intends to do and possible security implications of turning off the default validation ([PR 217](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/pull/217)).


## Features
* **JsonWebKey:** Upgraded to fully support features in http://tools.ietf.org/html/draft-ietf-jose-json-web-key-37
* **Logging:** Added Event Source based logging in Wilson. `IdentityModelEventSource` is the exposed event source handle.
* The OM removed support for `SecurityTokens` for crypto operations

## Breaking Changes

* **NOTE:** We have not added support for WsFederation and Saml in this version yet.
* **Refactoring**
    * `Microsoft.IdentityModel.Protocol.Extensions` is refactored into:
        * **Microsoft.IdentityModel.Protocol**: Includes protocol agnostic classes, e.g. `ConfigurationManager`.
        * **Microsoft.IdentityModel.Protocols.OpenIdConnect**: Includes OpenIdConnect specific support like `OpenIdConnectMessage`, `OpenIdConnectConfiguration`, `OpenIdConnectProtocolValidation` etc.
        * **Microsoft.IdentityModel.Protocols.WsFederation**: Includes stubs for `WsFederation` support.
    * `System.IdentityModel.Tokens` is refactored into:
        * **System.IdentityModel.Tokens**: Includes support for crypto operations and other classes that are not token format specific e.g. `TokenValidationParameters`.
        * **System.IdentityModel.Tokens.Jwt**: Includes classes for handling jwt tokens like `JwtSecurityTokenHandler`.
        * **System.IdentityModel.Tokens.Saml**: Includes stubs for handling Saml tokens.
* **Microsoft.IdentityModel.Protocol.Extensions** (now refactored as detailed above)
    * **Removed:**
        * `SecurityTokenHandlerCollectionExtensions` class has been replaced by `IList<ISecurityTokenValidator>`.
        * `OpenIdConnectConfiguration.SigningTokens`: The model has been redesigned to specify only keys for crypto operattion.
        * Following constructors have been removed to facilitate release of Beta5 since `SerializationInfo` is not supported in FxCore:
            * `OpenIdConnectProtocolException.OpenIdConnectProtocolException(SerializationInfo info, StreamingContext context)`.
            * `OpenIdConnectProtocolInvalidCHashException.OpenIdConnectProtocolInvalidCHashException(SerializationInfo info, StreamingContext context)`.
            * `OpenIdConnectProtocolInvalidNonceException.OpenIdConnectProtocolInvalidNonceException(SerializationInfo info, StreamingContext context)`.
    * **Changed:**
        * Type of `ClientDecryptionTokens` has been changed from `ReadOnlyCollection<SecurityToken>` to `IList<SecurityToken>`.
        * `JsonWebKey.KeyOps` OM changed from `string` to `IList<string>` as per specifications.
        * `JsonWebKeySet.GetSigningTokens()` has been replaced by `JsonWebKeySet.GetSigningKeys()`.
    * **Added:**
        * public class `ErrorMessages`. List of all messages that we log and/or throw.
        * public class `Base64UrlEncoder`. It provides APIs to read and write Json objects.
        * `JsonWebKeyParameterNames` now has more members to support Elliptic and RSA public/private keys as per https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37.
        * `OpenIdConnectConfiguration Create(string json)`.
* **System.IdentityModel.Tokens** (now refactored as detailed above)
    * **Removed:**  
        * `SecurityTokenDescriptor`. Temporarily removed while redesiging. We have an issue tracking this: [#80](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/80)
        * Following properties are removed because `kid` property is added to `JwtHeader` class:
            * `SecurityKeyIdentifier`
            * `SecurityKeyIdentifierClause`
            * `JwtHeader.SigningKeyIdentifier`
        * Following constructors have been removed to facilitate release of Beta5 since `SerializationInfo` is not supported in FxCore:
            * `SecurityTokenInvalidAudienceException.SecurityTokenInvalidAudienceException(SerializationInfo info, StreamingContext context)`.
            * `SecurityTokenInvalidIssuerException.SecurityTokenInvalidIssuerException(SerializationInfo info, StreamingContext context)`.
            * `SecurityTokenInvalidLifetimeException.SecurityTokenInvalidLifetimeException(SerializationInfo info, StreamingContext context)`.
        * `IssuerSigningToken` and `IssuerSigningTokens` have been removed from `TokenValidationParameters`.
        * `JwtSecurityTokenHandler`:
            * `public override bool CanReadToken(XmlReader reader)`: Xml tokens are not supported for jwt
            * `public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)`: Replaced with simpler 'kid'
            * `public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)`: Temporarily removed while redesiging: [#80](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/80)
            * `public override string[] GetTokenTypeIdentifiers()`: Removed with `ValidateToken(SecurityToken)` because the type is not known until the signature is validated. There is some refactoring work underway where `ValidateToken(SecurityToken)` would makes sense in the ProtocolLayer (OIDC for example).
            * `public override void LoadCustomConfiguration(XmlNodeList nodelist)`: `Web.config` has been replaced with `TokenValidationParameters`
            * `public override SecurityToken ReadToken(XmlReader reader)`: Wrapped tokens in soap envelopes are not supported (if asked for we could bring this back).
            * `public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)`: Signature Validation requires the original credentials from the wire (string). All validation is handled in the same flow. See comments in `GetTokenTypeIdentifiers`.
            * `public override void WriteToken(XmlWriter writer, SecurityToken token)`: Wrapped tokens in soap envelopes are not supported (if asked for we could bring this back)
        * Classes Removed. These were not needed after adding the `kid` property:
            * public class NamedKeyIssuerTokenResolver
            * public class NamedKeySecurityKeyIdentifierClause
            * public class NamedKeySecurityToken
    * **Changed:**
        * `ErrorMessages` class has been moved from Microsoft.IdentityModel to System.IdentityModel.Tokens.
        * `JwtHeader` constructor: `JwtHeader(SigningCredentials signingCredentials)` does not assign a default null value to `signingCredentials` if not passed.
        *  `AsymmetricAlgorithm` has been replaced by `SignatureProvider`.
        *  `X509AsymmetricSecurityKey` has been replaced by `X509SecurityKey`.
        *  `JwtSecurityToken.SecurityKeys` has been replaced by `JwtSecurityToken.SecurityKey`. The token now contains a single key
        *  `JwtSecurityTOken.ResolveIssuerSigningKey(string token, SecurityToken securityToken, SecurityKeyIdentifier keyIdentifier, TokenValidationParameters validationParameters)` has been replaced by `ResolveIssuerSigningKey(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)`
        *  Taking a dependency on NewtonSoft resulted the type of the `Claim.Property[JwtSecurityTokenHandler.JsonClaimTypeProperty]` to change from `typeof(IDictionary<string, object>).ToString()` to `Newtonsoft.Json.Linq.JProperty`.
        *  `TokenValidationParameters.IssuerSigningKeyResolver` method takes a `string kid` instead of `SecurityKeyIdentifier keyIdentifier` as parameter.
        *  `JwtSecurityToken.SigningToken` has been replaced by `JwtSecurityToken.SigningKey`.
    *  **Added:**
        * Added properties `string Kid` and `string X5t` to `JwtHeader` class.
        * Added properties `DateTime ValidFrom` and `DateTime ValidTo` to `JwtPayload` class.
        * Added `SignatureValidator` delegate and `ValidateSignature` flag to `TokenValidationParameters`.
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