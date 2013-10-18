//-----------------------------------------------------------------------
// <copyright file="JwtErrors.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
// <license>
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
// </license>

namespace System.IdentityModel.Tokens
{
    using System.Diagnostics.CodeAnalysis;

    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed. Suppression is OK here.")]
    internal static class JwtErrors
    {
        // general errors 10000 - 10099
        internal const string Jwt10000 = "Jwt10000: The parameter '{0}' cannot be a 'null' or an empty string.";
        internal const string Jwt10001 = "Jwt10001: The property value '{0}' cannot be a 'null' or an empty string.";
        internal const string Jwt10002 = "Jwt10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.";

        // parsing errors 10100 - 10199
        internal const string Jwt10100 = "Jwt10100: Error found while parsing date time. The '{0}' claim has value '{1}' which is could not be parsed to an integer.\nInnerException: '{2}'.";
        internal const string Jwt10101 = "Jwt10101: Error found while parsing date time. The '{0}' claim has value '{1}' does not lie in the valid range. \nInnerException: '{2}'.";
        internal const string Jwt10105 = "Jwt10105: EncodingType attribute must be one of: '{0}', '{1}', '{2}'. Encodingtype found: '{3}' XML : '{4}'.";
        internal const string Jwt10106 = "Jwt10106: A NamedKey must specify the 'symmetricKey' attribute. XML received: '{0}'.";
        internal const string Jwt10107 = "Jwt10107: A NamedKey must specify the 'name' attribute. XML received: '{0}'.";
        internal const string Jwt10111 = "Jwt10111: timespan, must be greater than or equal to TimeSpan.Zero, was: '{0}'.";
        internal const string Jwt10112 = "Jwt10112: Jwt header type specified, must be '{0}' or '{1}'.  Type received: '{2}'.";
        internal const string Jwt10113 = "Jwt10113: Unable to decode the '{0}': '{1}' as Base64url encoded string. jwtEncodedString: '{2}'.";
        internal const string Jwt10114 = "Jwt10114: Unable to decode: '{0}' as Base64url encoded string.";
        internal const string Jwt10115 = "Jwt10115: DefaultTokenLifetimeInMinutes cannot be set to 0.";
        internal const string Jwt10116 = "Jwt10116: MaximumTokenSizeInBytes cannot be set to 0.";
        internal const string Jwt10117 = "Jwt10117: Cannot set inner IssuerTokenResolver to self.";
        internal const string Jwt10118 = "Jwt10118: The SigningKeyIdentifier was of type: '{0}' and was expected to be encoded as a Base64UrlEncoded string. See inner exception for more details.";

        // JwtSecurityTokenHandler errors 10200 - 10299
        internal const string Jwt10200 = "Jwt10200: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.";
        internal const string Jwt10203 = "Jwt10203: '{0}' cannot read this xml: '{1}'. The reader needs to be positioned at an element: '{2}', within the namespace: '{3}', with an attribute: '{4}' equal to one of the following: '{5}', '{6}'.";
        internal const string Jwt10204 = "Jwt10204: '{0}' cannot read this string: '{1}'.\nThe string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEndcodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        internal const string Jwt10205 = "Jwt10205: Unable to validate token. this.Configuration is null. In code you can set the JwtSecurityTokenHandler.Configuration property.";
        internal const string Jwt10206 = "Jwt10206: jwtEncodedString has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'. In code you can set the JwtSecurityTokenHandler.MaximumTokenSizeInBytes property. In config use the 'jwtSecurityTokenRequirement' element and set the 'maximumTokenSizeInBytes' attribute.";

        // TokenValidation errors 10300 - 10399
        internal const string Jwt10300 = "Jwt10300: Unable to validate audience. jwt.Audience is null or whitespace only.";
        internal const string Jwt10301 = "Jwt10301: Unable to validate audience. validationParameters.AllowedAudience is null or whitespace and validationParameters.AllowedAudiences is null.";
        internal const string Jwt10303 = "Jwt10303: Audience validation failed. jwt.Audience: '{0}'. Could not match:  validationParameters.AllowedAudience: '{1}' and validationParameters.AllowedAudiences: '{2}'";
        internal const string Jwt10304 = "Jwt10304: The Configuration.ClockSkew cannot be less that Timespan.Zero, was: '{0}'.";
        internal const string Jwt10305 = "Jwt10305: Lifetime validation failed. The token is expired.\nValidTo: '{0}'\nCurrent time: '{1}'.";
        internal const string Jwt10306 = "Jwt10306: Lifetime validation failed. The token is not yet valid.\nValidFrom: '{0}'\nCurrent time: '{1}'.";
        internal const string Jwt10307 = "Jwt10307: The clockSkew specified canot be greater than unit.MaxInt, was: '{0}'.";
        internal const string Jwt10308 = "Jwt10308: Can only validate tokens of type: '{0}'. Was passed token of type: '{1}'.";
        internal const string Jwt10309 = "Jwt10309: Unable to validate signature.  Both validationParamters.SigningToken and validationParameters.SigningTokens are null. There is no key available to check the signature.";
        internal const string Jwt10311 = "Jwt10311: Unable to validate issuer, validationParameters.ValidIssuer: '{0}' or validationParameters.ValidIssuers: '{1}' did not match Jwt.Issuer: '{2}'. Comparison is: Equals ";
        internal const string Jwt10312 = "Jwt10312: Unable to validate signature, jwt does not have a signature: '{0}'";
        internal const string Jwt10314 = "Jwt10314: SignatureProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        internal const string Jwt10315 = "Jwt10315: Signature validation failed. Keys tried: '{0}'.\njwt: '{1}'";
        internal const string Jwt10316 = "Jwt10316: Signature validation failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\njwt: '{2}'";
        internal const string Jwt10317 = "Jwt10317: Unable to validate issuer. validationParameters.ValidIssuer is null or whitespace AND validationParameters.ValidIssuers is null.";
        internal const string Jwt10318 = "Jwt10318: Issuer validation failed. Configuration.IssuerNameRegistry.GetIssuerName returned a null or empty string. jwt.Issuer: '{0}'";
        internal const string Jwt10319 = "Jwt10319: Issuer validation failed. jwt.Issuer is null or whitespace.";
        internal const string Jwt10320 = "Jwt10320: Unable to validate signature, JwtHeader specifies: [ alg, '{0}' ] as the signature algorithm, it should specify a valid signature algorithm.\njwt: '{1}'.";        
        internal const string Jwt10322 = "Jwt10322: Lifetime validation failed. The token is missing the 'exp' (Expiration Time) claim.\njwt: '{0}'.";
        internal const string Jwt10323 = "Jwt10323: MaximumTokenSize must be greater than zero. value: '{0}'";
        internal const string Jwt10328 = "Jwt10328: Unable to validate signature. Configuration.IssuerTokenResolver is null.";
        internal const string Jwt10329 = "Jwt10329: Unable to validate signature, Configuration.IssuerTokenResolver.ResolveToken returned null. jwt.Header.SigningKeyIdentifier: '{0}'.";
        internal const string Jwt10330 = "Jwt10330: Unable to validate issuer. Configuration.IssuerNameRegistry is null.";
        internal const string Jwt10331 = "Jwt10331: Unable to create signature. '{0}' returned a null '{1}'. SecurityKey: '{2}', Algorithm: '{3}'";
        internal const string Jwt10332 = "Jwt10332: Audience validation failed. jwt.Audience: '{0}'.";

        internal const string NoNonNullKeysFound = "No non-null SecurityKeys were found";
        internal const string KeysTried          = "{0}";

        // JwtSecurityToken errors 10400 - 10499
        internal const string Jwt10400 = "Jwt10400: '{0}' is not well formed: '{1}'. The string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEndcodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        internal const string Jwt10401 = "Jwt10401: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'";
        internal const string Jwt10403 = "Jwt10403: Invalid dates. validFrom: '{0}' > validTo: {1}.";

        // CryptoErrors 10500 - 10599
        internal const string Jwt10500 = "Jwt10500: '{0}' supports: '{1}' of types: '{2}' or '{3}'. SecurityKey received was of type: '{4}'.";
        internal const string Jwt10503 = "Jwt10503: The '{0}' cannot have less than: '{1}' bits.";
        internal const string Jwt10511 = "Jwt10511: AsymmetricSecurityKey.GetHashAlgorithmForSignature( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}'";
        internal const string Jwt10513 = "Jwt10513: Cannot set the MinimumAsymmetricKeySizeInBitsForSigning to less than: '{0}'.";
        internal const string Jwt10514 = "Jwt10514: AsymmetricSecurityKey.GetSignatureFormater( '{0}' ) threw an exception.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException:'{2}'.\nIf you only need to verify signatures the parameter 'willBeUseForSigning' should be false if the private key is not be available.";
        internal const string Jwt10515 = "Jwt10515: AsymmetricSecurityKey.GetSignatureFormater( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        internal const string Jwt10516 = "Jwt10516: AsymmetricSecurityKey.GetSignatureDeformatter( '{0}' ) threw an exception.\nKey: '{1}'\nSignatureAlgorithm: '{0}, check to make sure the SignatureAlgorithm is supported.'\nException:'{2}'.";
        internal const string Jwt10517 = "Jwt10517: AsymmetricSecurityKey.GetSignatureDeFormater( '{0}' ) returned null.\nKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        internal const string Jwt10518 = "Jwt10518: AsymmetricSecurityKey.GetHashAlgorithmForSignature( '{0}' ) threw an exception.\nAsymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";
        internal const string Jwt10520 = "Jwt10520: The AsymmetricSignatureFormatter is null, cannot sign data.  Was this AsymmetricSignatureProvider constructor called specifying setting parameter: 'willCreateSignatures' == 'true'?.";
        internal const string Jwt10521 = "Jwt10521: This AsymmetricSignatureProvider has a minimum key size requirement of: '{0}', the AsymmetricSecurityKey in has a KeySize of: '{1}'.";
        internal const string Jwt10523 = "Jwt10523: The KeyedHashAlgorithm is null, cannot sign data.";
        internal const string Jwt10524 = "Jwt10524: Cannot sign 'input' byte array has length 0.";
        internal const string Jwt10525 = "Jwt10525: Cannot verify signature 'input' byte array has length 0.";
        internal const string Jwt10526 = "Jwt10526: Cannot verify signature 'signature' byte array has length 0.";
        internal const string Jwt10527 = "Jwt10527: Cannot set the MinimumAsymmetricKeySizeInBitsForVerifying to less than: '{0}'.";
        internal const string Jwt10528 = "Jwt10528: Cannot set the MinimumSymmetricKeySizeInBits to less than: '{0}'.";
        internal const string Jwt10529 = "Jwt10529: The AsymmetricSignatureDeformatter is null, cannot sign data. If a derived AsymmetricSignatureProvider is being used, make sure to call the base constructor.";
        internal const string Jwt10530 = "Jwt10530: The '{0}' for signing cannot be smaller than '{1}' bits.";
        internal const string Jwt10531 = "Jwt10531: The '{0}' for verifying cannot be smaller than '{1}' bits.";
        internal const string Jwt10532 = "Jwt10532: SymmetricSecurityKey.GetKeyedHashAlgorithm( '{0}' ) threw and exception.\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";
        internal const string Jwt10533 = "Jwt10533: SymmetricSecurityKey.GetKeyedHashAlgorithm( '{0}' ) returned null.\n\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}', check to make sure the SignatureAlgorithm is supported.";
        internal const string Jwt10534 = "Jwt10534: KeyedHashAlgorithm.Key = SymmetricSecurityKey.GetSymmetricKey() threw.\n\nSymmetricSecurityKey: '{1}'\nSignatureAlgorithm: '{0}' check to make sure the SignatureAlgorithm is supported.\nException: '{2}'.";

        // JwtSecurityTokenHandler configuration errors 10600 - 10699
        internal const string Jwt10600 = "Jwt10600: Attribute: '{0}' is null or whitespace.\nelement.OuterXml: '{1}'.";
        internal const string Jwt10601 = "Jwt10601: element.LocalName 'jwtSecurityTokenRequirement' was expected. found: '{0}'.\nelement.OuterXml: '{1}'.";
        internal const string Jwt10603 = "Jwt10603: Unable to process element: '{0}', see inner exception for details.\nelement.OuterXml: '{1}'.\nInnerException: '{2}'.";
        internal const string Jwt10606 = "Jwt10606: Attribute: '{0}' has an unrecognized attribute value: '{1}'.\nValid values are: '{2}' (all values are case insensitive).\nelement.OuterXml: '{3}'.";
        internal const string Jwt10607 = "Jwt10607: Element: '{0}' is expected to have the attribute '{1}'. The attribute was not found.\nelement.OuterXml: '{2}'.";
        internal const string Jwt10608 = "Jwt10608: Element: '{0}' has an unrecognized attribute: '{1}'.\nelement.OuterXml: '{2}'.";
        internal const string Jwt10609 = "Jwt10609: Element: '{0}' is expected to have only one attribute '{1}', multiple attributes were found.\nelement.OuterXml: '{2}'.";
        internal const string Jwt10610 = "Jwt10610: Element: '{0}' is expected to have the attribute '{1}'. Found unexpected attribute: '{2}'.\nelement.OuterXml: '{3}'.";
        internal const string Jwt10611 = "Jwt10611: '{0}' has an unrecognized element: '{1}'.\nValid elements are: '{2}' (all values are case sensitive).\nelement.OuterXml: '{3}'.";
        internal const string Jwt10612 = "Jwt10612: '{0}' attribute was 'Custom' but the '{1}' attribute was not found. The '{1}' attribute must be specified as it contains the 'type' of the X509CertificateValidator to instantiate when validating the X509Certificate that signed the token.\nelement.OuterXml: '{2}'.";
        internal const string Jwt10613 = "Jwt10613: Type.GetType( '{0}' ) did not succeed with type specified in the attribute '{1}'. Exception caught was: '{2}'.\nelement.OuterXml: '{3}'.";
        internal const string Jwt10614 = "Jwt10614: the 'validationMode' is not supported '{0}'.  Supported values are: 'ChainTrust, PeerTrust, PeerOrChainTrust, None'.";
        internal const string Jwt10616 = "Jwt10616: Element: '{0}' is duplicated. Each element can only occur once.\nelement.OuterXml: '{1}'.";
        internal const string Jwt10617 = "Jwt10617: Attribute: '{0}' is duplicated. Each attribute can only occur once.\nelement.OuterXml: '{1}'.";
        internal const string Jwt10619 = "Jwt10619: Specifying the: '{0}' attribute requires that the '{1}' attribute is set to: '{2}'.  It was set to: '{3}'. The runtime cannot determine if the '{4}' to be created, should be a standard one OR custom of type '{5}'.\nelement.OuterXml: '{6}'.";
    }
}