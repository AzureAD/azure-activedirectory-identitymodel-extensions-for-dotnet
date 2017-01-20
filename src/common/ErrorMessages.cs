//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;

namespace Microsoft.IdentityModel
{
    /// <summary>
    /// Error codes and messages
    /// </summary>
    [ SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed. Suppression is OK here.")]
    public static class ErrorMessages
    {
        #pragma warning disable 1591
        // general
        public const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty string.";
        public const string IDX10001 = "IDX10001: The property value '{0}' cannot be a 'null' or an empty string.";
        public const string IDX10002 = "IDX10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.";

        // protperties, configuration 
        public const string IDX10100 = "IDX10100: ClockSkew must be greater than TimeSpan.Zero. value: '{0}'";
        public const string IDX10101 = "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'";
        public const string IDX10102 = "IDX10102: NameClaimType cannot be null or whitespace.";
        public const string IDX10103 = "IDX10103: RoleClaimType cannot be null or whitespace.";
        public const string IDX10104 = "IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'";
        public const string IDX10105 = "IDX10105: NonceLifetime must be greater than zero. value: '{0}'";
        public const string IDX10106 = "IDX10106: When setting RefreshInterval, the value must be greater than MinimumRefreshInterval: '{0}'. value: '{1}'";
        public const string IDX10107 = "IDX10107: When setting AutomaticRefreshInterval, the value must be greater than MinimumAutomaticRefreshInterval: '{0}'. value: '{1}'";

        // token validation
        public const string IDX10200 = "IDX10200: Support for ValidateToken(string, TokenValidationParameters) requires a handler to implement ISecurityTokenValidator, none of the SecurityTokenHandlers did.";
        public const string IDX10201 = "IDX10201: None of the the SecurityTokenHandlers could read the 'securityToken': '{0}'.";
        public const string IDX10202 = "IDX10202: SamlToken.Assertion is null, can not create an identity. 'securityToken': '{0}'";
        public const string IDX10203 = "IDX10203: Unable to create ClaimsIdentity. Issuer is null or whitespace.";
        public const string IDX10204 = "IDX10204: Unable to validate issuer. validationParameters.ValidIssuer is null or whitespace AND validationParameters.ValidIssuers is null.";
        public const string IDX10205 = "IDX10205: Issuer validation failed. Issuer: '{0}'. Did not match: validationParameters.ValidIssuer: '{1}' or validationParameters.ValidIssuers: '{2}'.";
        public const string IDX10207 = "IDX10207: Unable to validate audience, o audiences to .";
        public const string IDX10208 = "IDX10208: Unable to validate audience. validationParameters.ValidAudience is null or whitespace and validationParameters.ValidAudiences is null.";
        public const string IDX10209 = "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.";
        public const string IDX10210 = "IDX10210: SamlToken.Assertion.Issuer is null, can not create an identity.";
        public const string IDX10211 = "IDX10211: Unable to validate issuer. The 'issuer' parameter is null or whitespace";
        public const string IDX10212 = "IDX10212: {0} can only validate tokens of type {1}.";
        public const string IDX10213 = "IDX10213: SecurityTokens must be signed. SecurityToken: '{0}'.";
        public const string IDX10214 = "IDX10214: Audience validation failed. Audiences: '{0}'. Did not match: validationParameters.ValidAudience: '{1}' or validationParameters.ValidAudiences: '{2}'";
        public const string IDX10215 = "IDX10215: Audience validation failed. Audiences passed in was null";
        public const string IDX10216 = "IDX10216: Lifetime validation failed. 'NotBefore' preceeds the current time: '{0}', ClockSkew (InSeconds): '{1}', notbefore: '{2}'";
        public const string IDX10217 = "IDX10217: Lifetime validation failed. 'NotOnOrAfter' is after the current time: '{0}', ClockSkew (InSeconds): '{1}', notbefore: '{2}'";
        public const string IDX10218 = "IDX10218: OneTimeUse is not supported";
        public const string IDX10219 = "IDX10219: ProxyRestriction is not supported";
        public const string IDX10220 = "IDX10220: Jwks_Uri must be an absolute uri. Was: ";
        public const string IDX10221 = "IDX10221: Unable to create claims from securityToken, 'issuer' is null or empty.";
        public const string IDX10222 = "IDX10222: Lifetime validation failed. The token is not yet valid.\nValidFrom: '{0}'\nCurrent time: '{1}'.";
        public const string IDX10223 = "IDX10223: Lifetime validation failed. The token is expired.\nValidTo: '{0}'\nCurrent time: '{1}'.";
        public const string IDX10224 = "IDX10224: Lifetime validation failed. The NotBefore: '{0}' is after Expires: '{1}'.";
        public const string IDX10225 = "IDX10225: Lifetime validation failed. The token is missing an Expiration Time.\nTokentype: '{0}'.";
        public const string IDX10226 = "IDX10226: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.";
        public const string IDX10227 = "IDX10227: TokenValidationParameters.TokenReplayCache is not null, indicating to check for token replay but the security token has no expiration time: token '{0}'.";
        public const string IDX10228 = "IDX10228: The securityToken has previously been validated, securityToken: '{0}'.";
        public const string IDX10229 = "IDX10229: TokenValidationParameters.TokenReplayCache was unable to add the securityToken: '{0}'.";
        public const string IDX10230 = "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.";
        public const string IDX10231 = "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.";
        public const string IDX10232 = "IDX10232: validationParameters.CertificateValidator and validationParameters.IssuerSigningKeyValidator are null. Validation of a X509SecurityKey requires that you set the CertificateValidator or IssuerSigningKeyValidator.";
        public const string IDX10233 = "IDX10233: validationParameters.IssuerSigningKeyValidator is null. Validation requires that you set the IssuerSigningKeyValidator.";

        // protocol validation
        public const string IDX10300 = "IDX10300: A claim of type: '{0}', was not found in the jwt: '{1}'.";
        public const string IDX10301 = "IDX10301: The 'nonce' found in the jwt token did not match the expected nonce.\nexpected: '{0}'\nfound in jwt: '{1}'.\njwt: '{2}'.";
        public const string IDX10303 = "IDX10303: The 'c_hash' claim was null or an empty string, jwt: '{0}'.";
        public const string IDX10304 = "IDX10304: The c_hash: '{0}' in the jwt did not validate with the authorizationCode: '{1}', algorithm: '{2}', jwt: '{3}'.";
        public const string IDX10306 = "IDX10306: The algorithm: '{0}' specified in the jwt header was unable to create a .Net hashAlgorithm, jwt: '{1}'. See inner exception for details.\nPossible solution is to ensure that the algorithm specified in the 'JwtHeader' is understood by .Net. You can make additions to the OpenIdConnectProtocolValidationParameters.AlgorithmMap to map algorithms from the 'Jwt' space to .Net. In .Net you can also make use of 'CryptoConfig' to map algorithms.";
        public const string IDX10307 = "IDX10307: The algorithm: '{0}' specified in the jwt header resulted in a hashAlgorithm that was null,  jwt: '{1}'.";
        public const string IDX10308 = "IDX10308: The 'c_hash' claim was not found in the jwt and validationContext.AuthorizationCode was not null therefore expected. jwt: '{0}'.";
        public const string IDX10309 = "IDX10309: OpenIdConnectProtocol requires the jwt token to have an '{0}' claim. The jwt did not contain an '{0}' claim, jwt: '{1}'.";
        public const string IDX10310 = "IDX10310: OpenIdConnectProtocol requires the jwt token to have a  valid 'aud' claim, jwt: '{0}'.";
        public const string IDX10311 = "IDX10311: RequireNonce is 'true' (default) but validationContext.Nonce is null. A nonce cannot be validated. If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.";
        public const string IDX10312 = "IDX10312: RequireAcr is 'true' (default is 'false') but jwt.PayLoad.Acr is 'null or whitespace', jwt: '{0}'.";
        public const string IDX10313 = "IDX10313: RequireAmr is 'true' (default is 'false') but jwt.PayLoad.Amr is 'null or whitespace', jwt: '{0}'.";
        public const string IDX10314 = "IDX10314: RequireAuthTime is 'true' (default is 'false') but jwt.PayLoad.AuthTime is 'null or whitespace', jwt: '{0}'.";
        public const string IDX10315 = "IDX10315: RequireAzp is 'true' (default is 'false') but jwt.PayLoad.Azp is 'null or whitespace', jwt: '{0}'.";
        public const string IDX10316 = "IDX10316: The 'nonce' has expired: '{0}'. Time from 'nonce': '{1}', Current Time: '{2}'. NonceLifetime is: '{3}'.";
        public const string IDX10317 = "IDX10317: The 'nonce' did not contain a timestamp: '{0}'.\nFormat expected is: <epochtime>.<noncedata>.";
        public const string IDX10318 = "IDX10318: The 'nonce' timestamp could not be converted to a positive integer (greater than 0).\ntimestamp: '{0}'\nnonce: '{1}'.";
        public const string IDX10319 = "IDX10319: The 'nonce' claim contains only whitespace, jwt: '{0}'.";
        public const string IDX10320 = "IDX10320: The 'nonce' timestamp: '{0}', could not be converted to a DateTime using DateTime.FromBinary({0}).\nThe value must be between: '{1}' and '{2}'.";
        public const string IDX10321 = "IDX10321: Ahe 'nonce' timestamp: '{0}', could not be converted to a DateTime using DateTime.FromBinary({0}).\nThe value must be between: '{1}' and '{2}'.";
        public const string IDX10322 = "IDX10322: RequireNonce is 'true' (default) but the jwt did not contain a 'nonce' claim. The nonce cannot be validated. If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.\n jwt: '{0}'.";
        public const string IDX10323 = "IDX10323: RequireNonce is 'false' (default is 'true') OpenIdConnectProtocolValidationContext.Nonce was NOT null, but the jwt did not contain a 'nonce' claim.\nOpenIdConnectProtocolValidationContext.Nonce: '{0}'\njwt: '{1}'.";

        // SecurityTokenHandler messages
        public const string IDX10400 = "IDX10400: The '{0}', can only process SecurityTokens of type: '{1}'. The SecurityToken received is of type: '{2}'.";
        public const string IDX10401 = "IDX10401: Expires: '{0}' must be after NotBefore: '{1}'.";

        // SignatureValidation
        public const string IDX10500 = "IDX10500: Signature validation failed. Unable to resolve SecurityKeyIdentifier: '{0}', \ntoken: '{1}'.";
        public const string IDX10501 = "IDX10501: Signature validation failed. Key tried: '{0}'.\ntoken: '{1}'";
        public const string IDX10502 = "IDX10502: Signature validation failed. Key tried: '{0}'.\nException caught:\n '{1}'.\ntoken: '{2}'";
        public const string IDX10503 = "IDX10503: Signature validation failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\ntoken: '{2}'";
        public const string IDX10504 = "IDX10504: Unable to validate signature, token does not have a signature: '{0}'";
        public const string IDX10505 = "IDX10505: Unable to validate signature. The 'Delegate' specified on TokenValidationParameters, returned a null SecurityKey.\nSecurityKeyIdentifier: '{0}'\nToken: '{1}'.";
        public const string IDX10506 = "IDX10506: Unable to validate signature. The token contained a KeyInfo, but it could not be matched against any of the provided keys. You can try refreshing metadata or your keys if they are provided directly.\nToken: {0}";

        // Crypto Errors
        public const string IDX10600 = "IDX10600: '{0}' supports: '{1}' of types: '{2}' or '{3}'. SecurityKey received was of type: '{4}'.";
        public const string IDX10603 = "IDX10603: The '{0}' cannot have less than: '{1}' bits.";
        public const string IDX10611 = "IDX10611: AsymmetricSecurityKey.GetHashAlgorithmForSignature( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}'";
        public const string IDX10613 = "IDX10613: Cannot set the MinimumAsymmetricKeySizeInBitsForSigning to less than: '{0}'.";
        public const string IDX10614 = "IDX10614: AsymmetricSecurityKey.GetSignatureFormater( '{0}' ) threw an exception.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException:'{2}'.\nIf you only need to verify signatures the parameter 'willBeUseForSigning' should be false if the private key is not be available.";
        public const string IDX10615 = "IDX10615: AsymmetricSecurityKey.GetSignatureFormater( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        public const string IDX10616 = "IDX10616: AsymmetricSecurityKey.GetSignatureDeformatter( '{0}' ) threw an exception.\nKey: '{1}'\nSignatureAlgorithm: '{0}, check to make sure the SignatureAlgorithm is supported.'\nException:'{2}'.";
        public const string IDX10617 = "IDX10617: AsymmetricSecurityKey.GetSignatureDeFormater( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        public const string IDX10618 = "IDX10618: AsymmetricSecurityKey.GetHashAlgorithmForSignature( '{0}' ) threw an exception.\nAsymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";
        public const string IDX10620 = "IDX10620: The AsymmetricSignatureFormatter is null, cannot sign data.  Was this AsymmetricSignatureProvider constructor called specifying setting parameter: 'willCreateSignatures' == 'true'?.";
        public const string IDX10621 = "IDX10621: This AsymmetricSignatureProvider has a minimum key size requirement of: '{0}', the AsymmetricSecurityKey in has a KeySize of: '{1}'.";
        public const string IDX10623 = "IDX10623: The KeyedHashAlgorithm is null, cannot sign data.";
        public const string IDX10624 = "IDX10624: Cannot sign 'input' byte array has length 0.";
        public const string IDX10625 = "IDX10625: Cannot verify signature 'input' byte array has length 0.";
        public const string IDX10626 = "IDX10626: Cannot verify signature 'signature' byte array has length 0.";
        public const string IDX10627 = "IDX10627: Cannot set the MinimumAsymmetricKeySizeInBitsForVerifying to less than: '{0}'.";
        public const string IDX10628 = "IDX10628: Cannot set the MinimumSymmetricKeySizeInBits to less than: '{0}'.";
        public const string IDX10629 = "IDX10629: The AsymmetricSignatureDeformatter is null, cannot sign data. If a derived AsymmetricSignatureProvider is being used, make sure to call the base constructor.";
        public const string IDX10630 = "IDX10630: The '{0}' for signing cannot be smaller than '{1}' bits.";
        public const string IDX10631 = "IDX10631: The '{0}' for verifying cannot be smaller than '{1}' bits.";
        public const string IDX10632 = "IDX10632: SymmetricSecurityKey.GetKeyedHashAlgorithm( '{0}' ) threw an exception.\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";
        public const string IDX10633 = "IDX10633: SymmetricSecurityKey.GetKeyedHashAlgorithm( '{0}' ) returned null.\n\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        public const string IDX10634 = "IDX10634: KeyedHashAlgorithm.Key = SymmetricSecurityKey.GetSymmetricKey() threw.\n\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}' check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";
        public const string IDX10635 = "IDX10635: Unable to create signature. '{0}' returned a null '{1}'. SecurityKey: '{2}', Algorithm: '{3}'";
        public const string IDX10636 = "IDX10636: SignatureProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        public const string IDX10637 = "IDX10637: the 'validationMode' is not supported '{0}'.  Supported values are: 'ChainTrust, PeerTrust, PeerOrChainTrust, None'.";

        // JWT specific errors
        public const string IDX10700 = "IDX10700: Error found while parsing date time. The '{0}' claim has value '{1}' which is could not be parsed to an integer.\nInnerException: '{2}'.";
        public const string IDX10701 = "IDX10701: Error found while parsing date time. The '{0}' claim has value '{1}' does not lie in the valid range. \nInnerException: '{2}'.";
        public const string IDX10702 = "IDX10702: Jwt header type specified, must be '{0}' or '{1}'.  Type received: '{2}'.";
        public const string IDX10703 = "IDX10703: Unable to decode the '{0}': '{1}' as Base64url encoded string. jwtEncodedString: '{2}'.";
        public const string IDX10704 = "IDX10704: Cannot set inner IssuerTokenResolver to self.";
        public const string IDX10705 = "IDX10705: The SigningKeyIdentifier was of type: '{0}' and was expected to be encoded as a Base64UrlEncoded string. See inner exception for more details.";
        public const string IDX10706 = "IDX10706: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.";
        public const string IDX10707 = "IDX10707: '{0}' cannot read this xml: '{1}'. The reader needs to be positioned at an element: '{2}', within the namespace: '{3}', with an attribute: '{4}' equal to one of the following: '{5}', '{6}'.";
        public const string IDX10708 = "IDX10708: '{0}' cannot read this string: '{1}'.\nThe string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEncodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        public const string IDX10709 = "IDX10709: '{0}' is not well formed: '{1}'. The string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEncodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        public const string IDX10710 = "IDX10710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'";

        // configuration retrieval errors
        public const string IDX10800 = "IDX10800: JsonWebKeySet must have a 'Keys' element.";
        public const string IDX10801 = "IDX10801: Unable to create an RSA public key from the Exponent and Modulus found in the JsonWebKey: E: '{0}', N: '{1}'. See inner exception for additional details.";
        public const string IDX10802 = "IDX10802: Unable to create an X509Certificate2 from the X509Data: '{0}'. See inner exception for additional details.";
        public const string IDX10803 = "IDX10803: Unable to create to obtain configuration from: '{0}'.";

        // NotSupported Exceptions
        public const string IDX11000 = "IDX11000: This method is not supported to validate a 'saml2token' use the method: ValidateToken(String, TokenValidationParameters, out SecurityToken).";
        public const string IDX11001 = "IDX11001: This method is not supported to validate a 'samltoken' use the method: ValidateToken(String, TokenValidationParameters, out SecurityToken).";
        public const string IDX11002 = "IDX11002: This method is not supported to read a 'saml2token' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        public const string IDX11003 = "IDX11003: This method is not supported to read a 'samltoken' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        public const string IDX11004 = "IDX11004: Loading from Configuration is not supported use TokenValidationParameters to set validation parameters.";
        public const string IDX11005 = "IDX11005: Creating a SecurityKeyIdentifierClause is not supported.";
        public const string IDX11006 = "IDX11006: This method is not supported to read a 'saml2token' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";
        public const string IDX11007 = "IDX11007: This method is not supported to read a 'samltoken' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";
        public const string IDX11008 = "IDX11008: This method is not supported to validate a 'jwt' use the method: ValidateToken(String, TokenValidationParameters, out SecurityToken).";

        // Loading from web.config
        public const string IDX13000 = "IDX13000: A NamedKey must specify the 'symmetricKey' attribute. XML received: '{0}'.";
        public const string IDX13001 = "IDX13001: A NamedKey must specify the 'name' attribute. XML received: '{0}'.";
        public const string IDX13002 = "IDX13002: Attribute: '{0}' is null or whitespace.\nelement.OuterXml: '{1}'.";
        public const string IDX13003 = "IDX13003: EncodingType attribute must be one of: '{0}', '{1}', '{2}'. Encodingtype found: '{3}' XML : '{4}'.";

        // utility errors
        public const string IDX14700 = "IDX14700: Unable to decode: '{0}' as Base64url encoded string.";

        #pragma warning restore 1591


    }
}
