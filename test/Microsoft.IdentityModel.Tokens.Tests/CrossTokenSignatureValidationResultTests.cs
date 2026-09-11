// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.TestUtils.Telemetry;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class CrossTokenSignatureValidationResultTests
    {
        public static TheoryData<string> HandlerKinds
        {
            get
            {
                var data = new TheoryData<string>();
                data.Add("Jwt");
                data.Add("Saml");
                data.Add("Saml2");
                return data;
            }
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task MatchingKey_ValidSignature_SetsSigningKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.True(result.Succeeded);
            Assert.Same(context.Key, result.Result.ValidatedSignatureKey);
            Assert.Same(context.Key, securityToken.SigningKey);
        }

        [Theory]
        [InlineData("Saml", false)]
        [InlineData("Saml", true)]
        [InlineData("Saml2", false)]
        [InlineData("Saml2", true)]
        public async Task SamlTryAllSigningKeys_ValidFallbackKey_SetsSigningKey(
            string handlerKind,
            bool tryInvalidKeyFirst)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            validationParameters.TryAllSigningKeys = true;
            using RSA wrongRsa = RSA.Create();
            wrongRsa.KeySize = 2048;
            if (tryInvalidKeyFirst)
                validationParameters.SigningKeys.Insert(0, new RsaSecurityKey(wrongRsa));

            SecurityToken securityToken = context.Handler.ReadToken(RemoveSamlKeyInfo(context.Token));

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Null(result.Error);
            Assert.Same(context.Key, result.Result.ValidatedSignatureKey);
            Assert.Same(context.Key, securityToken.SigningKey);
            Assert.Equal(tryInvalidKeyFirst ? 2 : 1, factory.CreateForVerifyingCount);
            Assert.Equal(factory.CreateForVerifyingCount, factory.ReleaseSignatureProviderCount);
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task SamlTryAllSigningKeys_InvalidFallbackKey_DoesNotSetSigningKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();
            using RSA wrongRsa = RSA.Create();
            wrongRsa.KeySize = 2048;
            ValidationParameters validationParameters = CreateValidationParameters(new RsaSecurityKey(wrongRsa), factory);
            validationParameters.TryAllSigningKeys = true;
            SecurityToken securityToken = context.Handler.ReadToken(RemoveSamlKeyInfo(context.Token));

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            Assert.Null(securityToken.SigningKey);
            Assert.Equal(SignatureValidationFailure.SigningKeyNotFound, result.Error.FailureType);
            Assert.Equal(1, factory.CreateForVerifyingCount);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task SamlTryAllSigningKeys_Disabled_DoesNotAttemptFallbackKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            validationParameters.TryAllSigningKeys = false;
            SecurityToken securityToken = context.Handler.ReadToken(RemoveSamlKeyInfo(context.Token));

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(securityToken.SigningKey);
            Assert.Equal(SignatureValidationFailure.SigningKeyNotFound, result.Error.FailureType);
            Assert.Equal(0, factory.CreateForVerifyingCount);
            Assert.Equal(0, factory.ReleaseSignatureProviderCount);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task ParameterFactory_RejectsAlgorithm_DoesNotCreateProvider(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            AssertFailedFactoryGuard(result, securityToken, factory, expectProviderCreated: false);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task KeyFactory_RejectsAlgorithm_WhenValidationParametersFactoryIsNull(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };
            context.Key.CryptoProviderFactory = factory;
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            validationParameters.CryptoProviderFactory = null;
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            AssertFailedFactoryGuard(result, securityToken, factory, expectProviderCreated: false);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task ParameterFactory_OverridesAcceptingKeyFactory(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            context.Key.CryptoProviderFactory = CryptoProviderFactory.Default;
            TrackingCryptoProviderFactory rejecting = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, rejecting);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            AssertFailedFactoryGuard(result, securityToken, rejecting, expectProviderCreated: false);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task ParameterFactory_OverridesRejectingKeyFactory(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            context.Key.CryptoProviderFactory = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, CryptoProviderFactory.Default);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.True(result.Succeeded);
            Assert.Same(context.Key, securityToken.SigningKey);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task FactoryReturnsNullProvider_PreservesNullProviderFailure(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { ReturnNullSignatureProvider = true };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(securityToken.SigningKey);
            Assert.Equal(ValidationFailureType.CryptoProviderReturnedNull, result.Error.FailureType);
            Assert.Contains("IDX10636", result.Error.Message, StringComparison.Ordinal);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task AlgorithmPolicyRejects_BeforeFactoryStage(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory, skipAlgorithm: false);
            validationParameters.ValidAlgorithms.Add(SecurityAlgorithms.HmacSha256);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.IsType<AlgorithmValidationError>(result.Error);
            Assert.Equal(AlgorithmValidationFailure.ValidationFailed, result.Error.FailureType);
            Assert.Equal(0, factory.CreateForVerifyingCount);
            Assert.Null(securityToken.SigningKey);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task CryptographicSignatureFails_DoesNotSetSigningKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            string tampered = TamperSignature(handlerKind, context.Token);
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            SecurityToken securityToken = context.Handler.ReadToken(tampered);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(securityToken.SigningKey);
            Assert.Equal(SignatureValidationFailure.ValidationFailed, result.Error.FailureType);
            Assert.Contains("IDX10520", result.Error.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task SamlDigestInvalid_ReturnsDigestErrorWithoutSigningKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind, uniqueClaimValue: "UNIQUE_DIGEST_PAYLOAD_VALUE");
            string tampered = context.Token.Replace("UNIQUE_DIGEST_PAYLOAD_VALUE", "TAMPERED_DIGEST_PAYLOAD_VALUE");
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            SecurityToken securityToken = context.Handler.ReadToken(tampered);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(securityToken.SigningKey);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, result.Error.FailureType);
            Assert.True(result.Error.StackFrames.Count >= 2);
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task SamlMalformedDigest_ReturnsDigestErrorWithoutSigningKey(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            SecurityToken securityToken = context.Handler.ReadToken(CreateSamlTokenWithMalformedDigest(context));

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            Assert.Null(securityToken.SigningKey);
            SignatureValidationError error = Assert.IsType<SignatureValidationError>(result.Error);
            Assert.IsType<FormatException>(error.InnerException);
            Assert.Contains("IDX30201", error.Message, StringComparison.Ordinal);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, error.FailureType);
            Assert.True(error.StackFrames.Count >= 3);
            SecurityTokenInvalidSignatureException exception = Assert.IsType<SecurityTokenInvalidSignatureException>(error.GetException());
            Assert.Same(error.InnerException, exception.InnerException);
            Assert.Equal(1, factory.CreateForVerifyingCount);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Theory]
        [InlineData("Saml", false)]
        [InlineData("Saml", true)]
        [InlineData("Saml2", false)]
        [InlineData("Saml2", true)]
        public async Task SamlDigestComputationFails_ReturnsDigestErrorWithoutSigningKey(
            string handlerKind,
            bool hashProviderThrows)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            CryptographicException hashException = hashProviderThrows ? new CryptographicException("hash-failed") : null;
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory
            {
                IsDigestAlgorithmSupported = hashProviderThrows,
                HashCreationException = hashException
            };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            Assert.Null(securityToken.SigningKey);
            SignatureValidationError error = Assert.IsType<SignatureValidationError>(result.Error);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, error.FailureType);
            Assert.Contains("IDX30201", error.Message, StringComparison.Ordinal);
            Assert.True(error.StackFrames.Count >= 3);
            if (hashProviderThrows)
                Assert.Same(hashException, error.InnerException);
            else
                Assert.Contains("IDX30208", Assert.IsType<XmlValidationException>(error.InnerException).Message, StringComparison.Ordinal);

            SecurityTokenInvalidSignatureException exception = Assert.IsType<SecurityTokenInvalidSignatureException>(error.GetException());
            Assert.Same(error.InnerException, exception.InnerException);
            Assert.Equal(1, factory.CreateForVerifyingCount);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Theory, MemberData(nameof(HandlerKinds), DisableDiscoveryEnumeration = true)]
        public async Task FactoryFailure_GetExceptionIsCachedAndNotAlgorithmException(string handlerKind)
        {
            // Arrange
            SignedTokenContext context = CreateSignedToken(handlerKind);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };
            ValidationParameters validationParameters = CreateValidationParameters(context.Key, factory);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(
                context.Handler, securityToken, validationParameters);

            // Assert
            Exception first = result.Error.GetException();
            Exception second = result.Error.GetException();
            Assert.Same(first, second);
            Assert.IsType<SignatureValidationError>(result.Error);
            Assert.IsType<SecurityTokenValidationException>(first);
            Assert.IsNotType<SecurityTokenInvalidSignatureException>(first);
            Assert.IsNotType<AlgorithmValidationError>(result.Error);
        }

        private static void AssertFailedFactoryGuard(
            ValidationResult<ValidatedToken, ValidationError> result,
            SecurityToken securityToken,
            TrackingCryptoProviderFactory factory,
            bool expectProviderCreated)
        {
            Assert.False(result.Succeeded);
            Assert.Null(securityToken.SigningKey);
            Assert.IsType<SignatureValidationError>(result.Error);
            Assert.Equal(ValidationFailureType.CryptoProviderFactoryDoesNotSupportAlgorithm, result.Error.FailureType);
            Assert.Contains("IDX10652", result.Error.Message, StringComparison.Ordinal);
            Assert.IsType<SecurityTokenValidationException>(result.Error.GetException());
            Assert.Equal(expectProviderCreated ? 1 : 0, factory.CreateForVerifyingCount);
        }

        private static Task<ValidationResult<ValidatedToken, ValidationError>> ValidateAsync(
            TokenHandler handler,
            SecurityToken securityToken,
            ValidationParameters validationParameters)
        {
            return ((IResultBasedValidation)handler).ValidateTokenAsync(
                securityToken,
                validationParameters,
                new CallContext(),
                CancellationToken.None);
        }

        private static ValidationParameters CreateValidationParameters(
            SecurityKey key,
            CryptoProviderFactory factory = null,
            bool skipAlgorithm = true)
        {
            ValidationParameters validationParameters = new ValidationParameters();
            validationParameters.SigningKeys.Add(key);
            if (factory != null)
                validationParameters.CryptoProviderFactory = factory;

            validationParameters.AudienceValidator = SkipValidationValidators.SkipAudienceValidation;
            validationParameters.SignatureKeyValidator = SkipValidationValidators.SkipIssuerSigningKeyValidation;
            validationParameters.IssuerValidatorAsync = SkipValidationValidators.SkipIssuerValidation;
            validationParameters.LifetimeValidator = SkipValidationValidators.SkipLifetimeValidation;
            validationParameters.TokenReplayValidator = SkipValidationValidators.SkipTokenReplayValidation;
            validationParameters.TokenTypeValidator = SkipValidationValidators.SkipTokenTypeValidation;
            if (skipAlgorithm)
                validationParameters.AlgorithmValidator = SkipValidationValidators.SkipAlgorithmValidation;

            return validationParameters;
        }

        private static SignedTokenContext CreateSignedToken(string handlerKind, string uniqueClaimValue = "cross-token-payload")
        {
            X509SecurityKey key = new X509SecurityKey(KeyingMaterial.DefaultCert_2048);
            SigningCredentials jwtCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
            SigningCredentials xmlCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            if (handlerKind == "Jwt")
            {
                JsonWebTokenHandler handler = new JsonWebTokenHandler();
                string token = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = Default.Issuer,
                    Audience = Default.Audience,
                    SigningCredentials = jwtCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(new[]
                    {
                        new Claim("unique", uniqueClaimValue)
                    })
                });
                return new SignedTokenContext(handler, token, key);
            }

            if (handlerKind == "Saml")
            {
                SamlSecurityTokenHandler handler = new SamlSecurityTokenHandler();
                SecurityToken securityToken = handler.CreateToken(CreateSamlDescriptor(xmlCredentials, uniqueClaimValue));
                return new SignedTokenContext(handler, handler.WriteToken(securityToken), key);
            }

            if (handlerKind == "Saml2")
            {
                Saml2SecurityTokenHandler handler = new Saml2SecurityTokenHandler();
                SecurityToken securityToken = handler.CreateToken(CreateSamlDescriptor(xmlCredentials, uniqueClaimValue));
                return new SignedTokenContext(handler, handler.WriteToken(securityToken), key);
            }

            throw new ArgumentOutOfRangeException(nameof(handlerKind), handlerKind, "Unknown handler kind.");
        }

        private static SecurityTokenDescriptor CreateSamlDescriptor(SigningCredentials credentials, string uniqueClaimValue)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                SigningCredentials = credentials,
                Subject = new CaseSensitiveClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, "Bob"),
                    new Claim(ClaimTypes.Email, uniqueClaimValue)
                })
            };
        }

        private static string RemoveSamlKeyInfo(string token)
        {
            XmlDocument document = new XmlDocument { PreserveWhitespace = true };
            document.LoadXml(token);
            XmlElement keyInfo = GetSignatureElement(document, XmlSignatureConstants.Elements.KeyInfo);
            keyInfo.ParentNode.RemoveChild(keyInfo);
            return document.OuterXml;
        }

        private static string CreateSamlTokenWithMalformedDigest(SignedTokenContext context)
        {
            XmlDocument document = new XmlDocument { PreserveWhitespace = true };
            document.LoadXml(context.Token);
            GetSignatureElement(document, XmlSignatureConstants.Elements.DigestValue).InnerText = "not-valid-base64!!!";

            Signature signature = context.Handler.ReadToken(document.OuterXml) switch
            {
                SamlSecurityToken samlToken => samlToken.Assertion.Signature,
                Saml2SecurityToken saml2Token => saml2Token.Assertion.Signature,
                _ => throw new ArgumentException("A SAML token handler is required.", nameof(context))
            };

            using MemoryStream canonicalBytes = new MemoryStream();
            signature.SignedInfo.GetCanonicalBytes(canonicalBytes);
            CryptoProviderFactory factory = context.Key.CryptoProviderFactory;
            SignatureProvider provider = factory.CreateForSigning(context.Key, signature.SignedInfo.SignatureMethod);
            try
            {
                GetSignatureElement(document, XmlSignatureConstants.Elements.SignatureValue).InnerText =
                    Convert.ToBase64String(provider.Sign(canonicalBytes.ToArray()));
            }
            finally
            {
                factory.ReleaseSignatureProvider(provider);
            }

            return document.OuterXml;
        }

        private static XmlElement GetSignatureElement(XmlDocument document, string elementName)
        {
            XmlNodeList elements = document.GetElementsByTagName(elementName, XmlSignatureConstants.Namespace);
            Assert.Equal(1, elements.Count);
            return Assert.IsType<XmlElement>(elements[0]);
        }

        private static string TamperSignature(string handlerKind, string token)
        {
            if (handlerKind == "Jwt")
            {
                string[] parts = token.Split('.');
                byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(parts[2]);
                signatureBytes[0] ^= 0xFF;
                parts[2] = Base64UrlEncoder.Encode(signatureBytes);
                return string.Join(".", parts);
            }

            int start = token.IndexOf("SignatureValue>", StringComparison.Ordinal);
            Assert.True(start >= 0, "Signed token did not contain a SignatureValue element.");
            start += "SignatureValue>".Length;
            int end = token.IndexOf("</", start, StringComparison.Ordinal);
            Assert.True(end > start, "Signed token did not contain a closing SignatureValue tag.");
            char[] chars = new char[end - start];
            token.CopyTo(start, chars, 0, chars.Length);
            chars[0] = chars[0] == 'A' ? 'B' : 'A';
            StringBuilder builder = new StringBuilder(token.Length);
            builder.Append(token, 0, start);
            builder.Append(chars);
            builder.Append(token, end, token.Length - end);
            return builder.ToString();
        }

        private sealed class SignedTokenContext
        {
            public SignedTokenContext(TokenHandler handler, string token, SecurityKey key)
            {
                Handler = handler;
                Token = token;
                Key = key;
            }

            public TokenHandler Handler { get; }
            public string Token { get; }
            public SecurityKey Key { get; }
        }

        private class TrackingCryptoProviderFactory : CryptoProviderFactory
        {
            public int CreateForVerifyingCount { get; private set; }
            public int ReleaseSignatureProviderCount { get; private set; }
            public bool IsAlgorithmSupported { get; set; } = true;
            public bool IsDigestAlgorithmSupported { get; set; } = true;
            public bool ReturnNullSignatureProvider { get; set; }
            public Exception HashCreationException { get; set; }

            public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => IsAlgorithmSupported;

            public override bool IsSupportedAlgorithm(string algorithm) => IsDigestAlgorithmSupported;

            public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
            {
                CreateForVerifyingCount++;
                if (ReturnNullSignatureProvider)
                    return null;
                return base.CreateForVerifying(key, algorithm);
            }

            public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
            {
                if (signatureProvider != null)
                {
                    ReleaseSignatureProviderCount++;
                    base.ReleaseSignatureProvider(signatureProvider);
                }
            }

            public override HashAlgorithm CreateHashAlgorithm(string algorithm)
            {
                if (HashCreationException != null)
                    throw HashCreationException;
                return base.CreateHashAlgorithm(algorithm);
            }
        }
    }

    [Collection("Telemetry Tests")]
    public class CrossTokenSignatureValidationTelemetryTests
    {
        const string ExpectedIssuer = "Default.Issuer.com";

        public CrossTokenSignatureValidationTelemetryTests()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { ExpectedIssuer });
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task DigestSuccess_EmitsNone(string handlerKind)
        {
            // Arrange
            using TestMeterListener listener = new TestMeterListener();
            SignedTokenContextAccessor context = SignedTokenContextAccessor.Create(handlerKind);
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            SecurityToken securityToken = context.Handler.ReadToken(context.Token);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                await ((IResultBasedValidation)context.Handler).ValidateTokenAsync(
                    securityToken, validationParameters, new CallContext(), CancellationToken.None);

            // Assert
            Assert.True(result.Succeeded);
            TelemetryAssertionHelpers.AssertTelemetryRecorded(
                listener,
                TelemetryDataRecorder.SignatureValidationCounterName,
                new Dictionary<string, object>
                {
                    { TelemetryConstants.ErrorTag, TelemetryConstants.SignatureValidationErrors.None }
                });
        }

        [Theory]
        [InlineData("Saml")]
        [InlineData("Saml2")]
        public async Task DigestFailure_EmitsSignatureVerificationFailed(string handlerKind)
        {
            // Arrange
            using TestMeterListener listener = new TestMeterListener();
            SignedTokenContextAccessor context = SignedTokenContextAccessor.Create(
                handlerKind, uniqueClaimValue: "UNIQUE_DIGEST_PAYLOAD_VALUE");
            string tampered = context.Token.Replace("UNIQUE_DIGEST_PAYLOAD_VALUE", "TAMPERED_DIGEST_PAYLOAD_VALUE");
            ValidationParameters validationParameters = CreateValidationParameters(context.Key);
            SecurityToken securityToken = context.Handler.ReadToken(tampered);

            // Act
            ValidationResult<ValidatedToken, ValidationError> result =
                await ((IResultBasedValidation)context.Handler).ValidateTokenAsync(
                    securityToken, validationParameters, new CallContext(), CancellationToken.None);

            // Assert
            Assert.False(result.Succeeded);
            TelemetryAssertionHelpers.AssertTelemetryRecorded(
                listener,
                TelemetryDataRecorder.SignatureValidationCounterName,
                new Dictionary<string, object>
                {
                    { TelemetryConstants.ErrorTag, TelemetryConstants.SignatureValidationErrors.SignatureVerificationFailed }
                });

            var measurements = listener.GetMeasurements(TelemetryDataRecorder.SignatureValidationCounterName);
            Assert.DoesNotContain(
                measurements,
                measurement => measurement.Tags.Any(
                    tag => tag.Key == TelemetryConstants.ErrorTag
                        && string.Equals(
                            tag.Value?.ToString(),
                            TelemetryConstants.SignatureValidationErrors.None,
                            StringComparison.Ordinal)));
        }

        private static ValidationParameters CreateValidationParameters(SecurityKey key)
        {
            ValidationParameters validationParameters = new ValidationParameters();
            validationParameters.SigningKeys.Add(key);
            validationParameters.AudienceValidator = SkipValidationValidators.SkipAudienceValidation;
            validationParameters.SignatureKeyValidator = SkipValidationValidators.SkipIssuerSigningKeyValidation;
            validationParameters.IssuerValidatorAsync = SkipValidationValidators.SkipIssuerValidation;
            validationParameters.LifetimeValidator = SkipValidationValidators.SkipLifetimeValidation;
            validationParameters.TokenReplayValidator = SkipValidationValidators.SkipTokenReplayValidation;
            validationParameters.TokenTypeValidator = SkipValidationValidators.SkipTokenTypeValidation;
            validationParameters.AlgorithmValidator = SkipValidationValidators.SkipAlgorithmValidation;
            return validationParameters;
        }

        private sealed class SignedTokenContextAccessor
        {
            public TokenHandler Handler { get; set; }
            public string Token { get; set; }
            public SecurityKey Key { get; set; }

            public static SignedTokenContextAccessor Create(string handlerKind, string uniqueClaimValue = "cross-token-payload")
            {
                X509SecurityKey key = new X509SecurityKey(KeyingMaterial.DefaultCert_2048);
                SigningCredentials xmlCredentials = new SigningCredentials(
                    key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
                SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    Issuer = Default.Issuer,
                    SigningCredentials = xmlCredentials,
                    Subject = new CaseSensitiveClaimsIdentity(new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, "Bob"),
                        new Claim(ClaimTypes.Email, uniqueClaimValue)
                    })
                };

                if (handlerKind == "Saml")
                {
                    SamlSecurityTokenHandler handler = new SamlSecurityTokenHandler();
                    SecurityToken securityToken = handler.CreateToken(descriptor);
                    return new SignedTokenContextAccessor
                    {
                        Handler = handler,
                        Token = handler.WriteToken(securityToken),
                        Key = key
                    };
                }

                Saml2SecurityTokenHandler saml2Handler = new Saml2SecurityTokenHandler();
                SecurityToken saml2Token = saml2Handler.CreateToken(descriptor);
                return new SignedTokenContextAccessor
                {
                    Handler = saml2Handler,
                    Token = saml2Handler.WriteToken(saml2Token),
                    Key = key
                };
            }
        }
    }
}
