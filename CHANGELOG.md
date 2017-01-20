<a name="5.0.0"></a>
# 5.1.3

## Features
* **JWE Support:** AES and RSA key wrap support
* Fix for breaking change introduced in 5.1.0

# 5.1.2

## Features
* **Rebuild:** Fix strong name signing issue

# 5.1.1

## Features
* **Security Fix:** IdentityModel Extensions library Microsoft.IdentityModel.Tokens has a known security vulnerability affecting version 5.1.0. Please update to >= 5.1.1 immediately. An updated package is available on NuGet. For more details, see the [security notice](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/SECURITY_NOTICE.md).

# 5.1.0

## Features
* **JWE Support:** Direct encryption supported on tokens

# 5.0.0

## Features
* **JsonWebKey:** Upgraded to fully support features in http://tools.ietf.org/html/draft-ietf-jose-json-web-key-37
* **Logging:** Added Event Source based logging in Wilson. `IdentityModelEventSource` is the exposed event source handle.
* **Cryptography:** Added support for Elliptical Curve (ECDsa) algorithm.

## Major Changes from 4.x
* Dropped support for WsFederation and Saml.
* `SecurityKey` is used for token validation instead of `SecurityToken`. 
* `CryptoProviderFactory` provides all the extensibility to control and customize crypto support.
* Dropped support for reading and writing JWT tokens embedded in XML.
* Removed dependency on `System.IdentityModel.dll`.
* Replaced `JavaScriptSerializer` with Json.Net serializer. Deserializing `int` results in an `Int64` object by default instead of `Int32`.
* Replaced the static ClaimType maps on `JwtSecurityTokenHandler` with instances.
* **Refactoring**
    * Microsoft.IdentityModel.Protocol.Extensions is refactored into:
        * **Microsoft.IdentityModel.Protocols**: Includes protocol agnostic classes, e.g. `ConfigurationManager`.
        * **Microsoft.IdentityModel.Protocols.OpenIdConnect**: Includes OpenIdConnect specific support e.g. `OpenIdConnectMessage`, `OpenIdConnectConfiguration`, `OpenIdConnectProtocolValidator` etc.
    * System.IdentityModel.Tokens is refactored into:
        * **Microsoft.IdentityModel.Tokens**: Includes support for crypto operations and other classes that are not token format specific e.g. `CryptoProviderFactory`, `TokenValidationParameters` etc.
        * **System.IdentityModel.Tokens.Jwt**: Includes classes for handling jwt tokens e.g. `JwtSecurityTokenHandler`.
* Click here for [full list of bug fixes in 5.x](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues?utf8=%E2%9C%93&q=is%3Aissue%20is%3Aclosed%20label%3A%22Fix%205.x%22%20).
