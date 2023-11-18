//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

// Microsoft.IdentityModel.Tokens
// Range: 10000 - 10999

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        // public const string IDX10000 = "IDX10000:";

        // properties, configuration 
        public const string IDX10101 = "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'";
        public const string IDX10100 = "IDX10100: ClockSkew must be greater than TimeSpan.Zero. value: '{0}'";
        public const string IDX10102 = "IDX10102: NameClaimType cannot be null or whitespace.";
        public const string IDX10103 = "IDX10103: RoleClaimType cannot be null or whitespace.";
        public const string IDX10104 = "IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'";

        // token validation
        public const string IDX10204 = "IDX10204: Unable to validate issuer. validationParameters.ValidIssuer is null or whitespace AND validationParameters.ValidIssuers is null.";
        public const string IDX10205 = "IDX10205: Issuer validation failed. Issuer: '{0}'. Did not match: validationParameters.ValidIssuer: '{1}' or validationParameters.ValidIssuers: '{2}'.";
        public const string IDX10207 = "IDX10207: Unable to validate audience. The 'audiences' parameter is null.";
        public const string IDX10208 = "IDX10208: Unable to validate audience. validationParameters.ValidAudience is null or whitespace and validationParameters.ValidAudiences is null.";
        public const string IDX10209 = "IDX10209: Token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.";
        public const string IDX10211 = "IDX10211: Unable to validate issuer. The 'issuer' parameter is null or whitespace";
        public const string IDX10214 = "IDX10214: Audience validation failed. Audiences: '{0}'. Did not match: validationParameters.ValidAudience: '{1}' or validationParameters.ValidAudiences: '{2}'.";
        public const string IDX10222 = "IDX10222: Lifetime validation failed. The token is not yet valid. ValidFrom: '{0}', Current time: '{1}'.";
        public const string IDX10223 = "IDX10223: Lifetime validation failed. The token is expired. ValidTo: '{0}', Current time: '{1}'.";
        public const string IDX10224 = "IDX10224: Lifetime validation failed. The NotBefore: '{0}' is after Expires: '{1}'.";
        public const string IDX10225 = "IDX10225: Lifetime validation failed. The token is missing an Expiration Time. Tokentype: '{0}'.";
        public const string IDX10227 = "IDX10227: TokenValidationParameters.TokenReplayCache is not null, indicating to check for token replay but the security token has no expiration time: token '{0}'.";
        public const string IDX10228 = "IDX10228: The securityToken has previously been validated, securityToken: '{0}'.";
        public const string IDX10229 = "IDX10229: TokenValidationParameters.TokenReplayCache was unable to add the securityToken: '{0}'.";
        public const string IDX10230 = "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.";
        public const string IDX10231 = "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.";
        public const string IDX10232 = "IDX10232: IssuerSigningKey validation failed. Delegate returned false, securityKey: '{0}'.";
        public const string IDX10233 = "IDX10233: ValidateAudience property on ValidationParameters is set to false. Exiting without validating the audience.";
        public const string IDX10234 = "IDX10234: Audience Validated.Audience: '{0}'";
        public const string IDX10235 = "IDX10235: ValidateIssuer property on ValidationParameters is set to false. Exiting without validating the issuer.";
        public const string IDX10236 = "IDX10236: Issuer Validated.Issuer: '{0}'";
        public const string IDX10237 = "IDX10237: ValidateIssuerSigningKey property on ValidationParameters is set to false. Exiting without validating the issuer signing key.";
        public const string IDX10238 = "IDX10238: ValidateLifetime property on ValidationParameters is set to false. Exiting without validating the lifetime.";
        public const string IDX10239 = "IDX10239: Lifetime of the token is valid.";
        public const string IDX10240 = "IDX10240: No token replay is detected.";
        public const string IDX10241 = "IDX10241: Security token validated. token: '{0}'.";
        public const string IDX10242 = "IDX10242: Security token: '{0}' has a valid signature.";
        public const string IDX10243 = "IDX10243: Reading issuer signing keys from validation parameters.";
        public const string IDX10244 = "IDX10244: Issuer is null or empty. Using runtime default for creating claims '{0}'.";
        public const string IDX10245 = "IDX10245: Creating claims identity from the validated token: '{0}'.";
        public const string IDX10246 = "IDX10246: ValidateTokenReplay property on ValidationParameters is set to false. Exiting without validating the token replay.";
        // public const string IDX10247 = "IDX10247:";
        public const string IDX10248 = "IDX10248: X509SecurityKey validation failed. The associated certificate is not yet valid. ValidFrom (UTC): '{0}', Current time (UTC): '{1}'.";
        public const string IDX10249 = "IDX10249: X509SecurityKey validation failed. The associated certificate has expired. ValidTo (UTC): '{0}', Current time (UTC): '{1}'.";
        public const string IDX10250 = "IDX10250: The associated certificate is valid. ValidFrom (UTC): '{0}', Current time (UTC): '{1}'.";
        public const string IDX10251 = "IDX10251: The associated certificate is valid. ValidTo (UTC): '{0}', Current time (UTC): '{1}'.";
        public const string IDX10252 = "IDX10252: RequireSignedTokens property on ValidationParameters is set to false and the issuer signing key is null. Exiting without validating the issuer signing key.";
        public const string IDX10253 = "IDX10253: RequireSignedTokens property on ValidationParameters is set to true, but the issuer signing key is null.";
        public const string IDX10254 = "IDX10254: '{0}.{1}' failed. The virtual method '{2}.{3}' returned null. If this method was overridden, ensure a valid '{4}' is returned.";
        public const string IDX10255 = "IDX10255: ValidTypes property on ValidationParameters is either null or empty. Exiting without validating the token type.";
        public const string IDX10256 = "IDX10256: Unable to validate the token type. TokenValidationParameters.ValidTypes is set, but the 'typ' header claim is null or empty.";
        public const string IDX10257 = "IDX10257: Token type validation failed. Type: '{0}'. Did not match: validationParameters.TokenTypes: '{1}'.";
        public const string IDX10258 = "IDX10258: Token type validated. Type: '{0}'.";

        // 10500 - SignatureValidation
        public const string IDX10500 = "IDX10500: Signature validation failed. No security keys were provided to validate the signature.";
        public const string IDX10501 = "IDX10501: Signature validation failed. Unable to match key: \nkid: '{0}'.\nExceptions caught:\n '{1}'. \ntoken: '{2}'.";
        public const string IDX10503 = "IDX10503: Signature validation failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\ntoken: '{2}'.";
        public const string IDX10504 = "IDX10504: Unable to validate signature, token does not have a signature: '{0}'.";
        public const string IDX10505 = "IDX10505: Signature validation failed. The user defined 'Delegate' specified on TokenValidationParameters returned null when validating token: '{0}'.";
        public const string IDX10506 = "IDX10506: Signature validation failed. The user defined 'Delegate' specified on TokenValidationParameters did not return a '{0}', but returned a '{1}' when validating token: '{2}'.";
        // public const string IDX10507 = "IDX10507:";
        public const string IDX10508 = "IDX10508: Signature validation failed. Signature is improperly formatted.";
        public const string IDX10509 = "IDX10509: Signature validation failed. The user defined 'Delegate' specified in TokenValidationParameters did not return a '{0}', but returned a '{1}' when reading token: '{2}'.";
        public const string IDX10510 = "IDX10510: Signature validation failed. The user defined 'Delegate' specified in TokenValidationParameters returned null when reading token: '{0}'.";
        public const string IDX10511 = "IDX10511: Signature validation failed. Keys tried: '{0}'. \nkid: '{1}'. \nExceptions caught:\n '{2}'.\ntoken: '{3}'.";

        // encryption / decryption
        // public const string IDX10600 = "IDX10600:";
        // public const string IDX10601 = "IDX10601:";
        public const string IDX10603 = "IDX10603: Decryption failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\ntoken: '{2}'";
        // public const string IDX10604 = "IDX10604:";
        // public const string IDX10605 = "IDX10605:";
        // public const string IDX10606 = "IDX10606:";
        public const string IDX10607 = "IDX10607: Decryption skipping key: '{0}', both validationParameters.CryptoProviderFactory and key.CryptoProviderFactory are null.";
        // public const string IDX10608 = "IDX10608:";
        public const string IDX10609 = "IDX10609: Decryption failed. No Keys tried: token: '{0}'.";
        public const string IDX10610 = "IDX10610: Decryption failed. Could not create decryption provider. Key: '{0}', Algorithm: '{1}'.";
        public const string IDX10611 = "IDX10611: Decryption failed. Encryption is not supported for: Algorithm: '{0}', SecurityKey: '{1}'.";
        public const string IDX10612 = "IDX10612: Decryption failed. Header.Enc is null or empty, it must be specified.";
        // public const string IDX10613 = "IDX10613:";
        // public const string IDX10614 = "IDX10614:";
        public const string IDX10615 = "IDX10615: Encryption failed. No support for: Algorithm: '{0}', SecurityKey: '{1}'.";
        public const string IDX10616 = "IDX10616: Encryption failed. EncryptionProvider failed for: Algorithm: '{0}', SecurityKey: '{1}'. See inner exception.";
        public const string IDX10617 = "IDX10617: Encryption failed. Keywrap is only supported for: '{0}', '{1}' and '{2}'. The content encryption specified is: '{3}'.";

        // Formating
        public const string IDX10400 = "IDX10400: Unable to decode: '{0}' as Base64url encoded string.";
        public const string IDX10401 = "IDX10401: Invalid requested key size. Valid key sizes are: 256, 384, and 512.";

        // Crypto Errors
        public const string IDX10621 = "IDX10621: '{0}' supports: '{1}' of types: '{2}' or '{3}'. SecurityKey received was of type '{4}'.";
        // public const string IDX10622 = "IDX10622:";
        // public const string IDX10623 = "IDX10623:";
        // public const string IDX10624 = "IDX10624:";
        // public const string IDX10627 = "IDX10627:";
        public const string IDX10628 = "IDX10628: Cannot set the MinimumSymmetricKeySizeInBits to less than '{0}'.";
        public const string IDX10630 = "IDX10630: The '{0}' for signing cannot be smaller than '{1}' bits. KeySize: '{2}'.";
        public const string IDX10631 = "IDX10631: The '{0}' for verifying cannot be smaller than '{1}' bits. KeySize: '{2}'.";
        public const string IDX10634 = "IDX10634: Unable to create the SignatureProvider.\nAlgorithm: '{0}', SecurityKey: '{1}'\n is not supported. The list of supported algorithms is available here: https://aka.ms/IdentityModel/supported-algorithms";
        // public const string IDX10635 = "IDX10635:";
        public const string IDX10636 = "IDX10636: CryptoProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        public const string IDX10638 = "IDX10638: Cannot create the SignatureProvider, 'key.HasPrivateKey' is false, cannot create signatures. Key: {0}.";
        public const string IDX10640 = "IDX10640: Algorithm is not supported: '{0}'.";
        // public const string IDX10641 = "IDX10641:";
        public const string IDX10642 = "IDX10642: Creating signature using the input: '{0}'.";
        public const string IDX10643 = "IDX10643: Comparing the signature created over the input with the token signature: '{0}'.";
        // public const string IDX10644 = "IDX10644:";
        public const string IDX10645 = "IDX10645: Elliptical Curve not supported for curveId: '{0}'";
        public const string IDX10646 = "IDX10646: A CustomCryptoProvider was set and returned 'true' for IsSupportedAlgorithm(Algorithm: '{0}', Key: '{1}'), but Create.(algorithm, args) as '{2}' == NULL.";
        public const string IDX10647 = "IDX10647: A CustomCryptoProvider was set and returned 'true' for IsSupportedAlgorithm(Algorithm: '{0}'), but Create.(algorithm, args) as '{1}' == NULL.";
        // public const string IDX10648 = "IDX10648:";
        public const string IDX10649 = "IDX10649: Failed to create a SymmetricSignatureProvider for the algorithm '{0}'.";
        public const string IDX10650 = "IDX10650: Failed to verify ciphertext with aad '{0}'; iv '{1}'; and authenticationTag '{2}'.";
        // public const string IDX10651 = "IDX10651:";
        public const string IDX10652 = "IDX10652: The algorithm '{0}' is not supported.";
        public const string IDX10653 = "IDX10653: The encryption algorithm '{0}' requires a key size of at least '{1}' bits. Key '{2}', is of size: '{3}'.";
        public const string IDX10654 = "IDX10654: Decryption failed. Cryptographic operation exception: '{0}'.";
        public const string IDX10655 = "IDX10655: 'length' must be greater than 1: '{0}'";
        // public const string IDX10656 = "IDX10656:";
        public const string IDX10657 = "IDX10657: The SecurityKey provided for the symmetric key wrap algorithm cannot be converted to byte array. Type is: '{0}'.";
        public const string IDX10658 = "IDX10658: WrapKey failed, exception from cryptographic operation: '{0}'";
        public const string IDX10659 = "IDX10659: UnwrapKey failed, exception from cryptographic operation: '{0}'";
        // public const string IDX10660 = "IDX10660:";
        public const string IDX10661 = "IDX10661: Unable to create the KeyWrapProvider.\nKeyWrapAlgorithm: '{0}', SecurityKey: '{1}'\n is not supported.";
        public const string IDX10662 = "IDX10662: The KeyWrap algorithm '{0}' requires a key size of '{1}' bits. Key '{2}', is of size:'{3}'.";
        public const string IDX10663 = "IDX10663: Failed to create symmetric algorithm with SecurityKey: '{0}', KeyWrapAlgorithm: '{1}'.";
        public const string IDX10664 = "IDX10664: The length of input must be a multiple of 64 bits. The input size is: '{0}' bits.";
        public const string IDX10665 = "IDX10665: Data is not authentic";
        public const string IDX10666 = "IDX10666: Unable to create KeyedHashAlgorithm for algorithm '{0}'.";
        public const string IDX10667 = "IDX10667: Unable to obtain required byte array for KeyHashAlgorithm from SecurityKey: '{0}'.";
        public const string IDX10668 = "IDX10668: Unable to create '{0}', algorithm '{1}'; key: '{2}' is not supported.";
        public const string IDX10669 = "IDX10669: Failed to create symmetric algorithm.";
        // public const string IDX10670 = "IDX10670:";
        // public const string IDX10671 = "IDX10671:";
        // public const string IDX10672 = "IDX10672:";
        // public const string IDX10673 = "IDX10673:";
        public const string IDX10674 = "IDX10674: JsonWebKeyConverter does not support SecurityKey of type: {0}";
        public const string IDX10675 = "IDX10675: The byte count of '{0}' must be less than or equal to '{1}', but was {2}.";
        // public const string IDX10676 = "IDX10676:";
        public const string IDX10677 = "IDX10677: GetKeyedHashAlgorithm threw, key: {0}, algorithm {1}.";
        // public const string IDX10678 = "IDX10678:";
        public const string IDX10679 = "IDX10679: Failed to decompress using algorithm '{0}'.";
        public const string IDX10680 = "IDX10680: Failed to compress using algorithm '{0}'.";
        // public const string IDX10681 = "IDX10681:";
        public const string IDX10682 = "IDX10682: Compression algorithm '{0}' is not supported.";
        // public const string IDX10683 = "IDX10683:";
        public const string IDX10684 = "IDX10684: Unable to convert the JsonWebKey to an AsymmetricSecurityKey. Algorithm: '{0}', Key: '{1}'.";
        public const string IDX10685 = "IDX10685: Unable to Sign, Internal SignFunction is not available.";
        public const string IDX10686 = "IDX10686: Unable to Verify, Internal VerifyFunction is not available.";
        public const string IDX10687 = "IDX10687: Unable to create a AsymmetricAdapter. For NET45 or NET451 only types: '{0}' or '{1}' are supported. RSA is of type: '{2}'..";
        //public const string IDX10688 = "IDX10688:"
        public const string IDX10689 = "IDX10689: Unable to create an ECDsa object. See inner exception for more details.";
        public const string IDX10690 = "IDX10690: ECDsa creation is not supported by NETSTANDARD1.4, when running on platforms other than Windows. For more details, see https://aka.ms/IdentityModel/create-ecdsa";
        //public const string IDX10691 = "IDX10691:"
        public const string IDX10692 = "IDX10692: The RSASS-PSS signature algorithm is not available on .NET 4.5 and .NET 4.5.1 targets. The list of supported algorithms is available here: https://aka.ms/IdentityModel/supported-algorithms";
        public const string IDX10693 = "IDX10693: RSACryptoServiceProvider doesn't support the RSASSA-PSS signature algorithm. The list of supported algorithms is available here: https://aka.ms/IdentityModel/supported-algorithms";
        public const string IDX10694 = "IDX10694: JsonWebKeyConverter threw attempting to convert JsonWebKey: '{0}'. Exception: '{1}'.";

        // security keys
        public const string IDX10700 = "IDX10700: {0} is unable to use 'rsaParameters'. {1} is null.";
        //public const string IDX10701 = "IDX10701:"
        //public const string IDX10702 = "IDX10702:"
        public const string IDX10703 = "IDX10703: Cannot create a '{0}', key length is zero.";
        public const string IDX10704 = "IDX10704: Cannot verify the key size. The SecurityKey is not or cannot be converted to an AsymmetricSecuritKey. SecurityKey: '{0}'.";

        // Json specific errors
        //public const string IDX10801 = "IDX10801:"
        //public const string IDX10802 = "IDX10802:"
        //public const string IDX10804 = "IDX10804:"
        public const string IDX10805 = "IDX10805: Error deserializing json: '{0}' into '{1}'.";
        public const string IDX10806 = "IDX10806: Deserializing json: '{0}' into '{1}'.";
        //public const string IDX10807 = "IDX10807:"
        public const string IDX10808 = "IDX10808: The 'use' parameter of a JsonWebKey: '{0}' was expected to be 'sig' or empty, but was '{1}'.";
        //public const string IDX10809 = "IDX10809:"
        public const string IDX10810 = "IDX10810: Unable to convert the JsonWebKey: '{0}' to a X509SecurityKey, RsaSecurityKey or ECDSASecurityKey.";
        //public const string IDX10811 = "IDX10811:"
        public const string IDX10812 = "IDX10812: Unable to create a {0} from the properties found in the JsonWebKey: '{1}'.";
        public const string IDX10813 = "IDX10813: Unable to create a {0} from the properties found in the JsonWebKey: '{1}', Exception '{2}'.";
        public const string IDX10814 = "IDX10814: Decompressing would result in a token with a size greater than allowed. Maximum size allowed: '{0}'.";

#pragma warning restore 1591
    }
}
