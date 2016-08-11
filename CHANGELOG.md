Version 1.0.3 (August 11, 2016)
========================== 
* Adding ConfigureAwait to avoid deadlock.
* Adding RefreshToken property to OpenIdConnectMessage and OpenIdConnectParameterNames.
* Saml and Saml2 handlers throw SignatureVerificationFailedException instead of SecurityTokenSignatureKeyNotFoundException when the securityKey is not found.
* User can set `SetDefaultTimesOnTokenCreation` property on `JwtSecurityTokenHandler` class to control nbf and expires values.
* Relaxing the requirement of "iss" on jwt token to create claims identity.
