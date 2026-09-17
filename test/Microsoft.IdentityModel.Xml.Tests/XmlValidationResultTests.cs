// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class XmlValidationResultTests
    {
        [Fact]
        public void ReferenceVerify_ValidDigest_ReturnsSameReference()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            CallContext callContext = new CallContext();

            // Act
            ValidationResult<Reference, ValidationError> result =
                reference.Verify(CryptoProviderFactory.Default, callContext);

            // Assert
            Assert.True(result.Succeeded);
            Assert.Same(reference, result.Result);
            Assert.Null(result.Error);
        }

        [Fact]
        public void ReferenceVerify_NullFactory_ReturnsNullArgument()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();

            // Act
            ValidationResult<Reference, ValidationError> result =
                reference.Verify(null, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            Assert.Equal(ValidationFailureType.NullArgument, result.Error.FailureType);
            Assert.Contains("cryptoProviderFactory", result.Error.Message, StringComparison.Ordinal);
            Assert.IsType<ArgumentNullException>(result.Error.GetException());
        }

        [Fact]
        public void ReferenceVerify_DigestMismatch_ReturnsDigestFailure()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            reference.DigestValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });

            // Act
            ValidationResult<Reference, ValidationError> result =
                reference.Verify(CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.IsType<SignatureValidationError>(result.Error);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, result.Error.FailureType);
            Assert.Contains("IDX30201", result.Error.Message, StringComparison.Ordinal);
            Assert.IsType<SecurityTokenInvalidSignatureException>(result.Error.GetException());
        }

        [Fact]
        public void ReferenceVerify_MalformedBase64_ReturnsDigestFailureAndReleasesHash()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            reference.DigestValue = "not-valid-base64!!!";
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();

            // Act
            ValidationResult<Reference, ValidationError> result = reference.Verify(factory, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            Assert.IsType<FormatException>(error.InnerException);
            Assert.Equal(factory.CreateHashAlgorithmCount, factory.ReleaseHashAlgorithmCount);
            Assert.True(factory.CreateHashAlgorithmCount > 0);
        }

        [Fact]
        public void ReferenceVerify_MissingStream_ReturnsDigestFailure()
        {
            // Arrange
            Reference reference = new Reference
            {
                DigestMethod = SecurityAlgorithms.Sha256Digest,
                DigestValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })
            };

            // Act
            ValidationResult<Reference, ValidationError> result =
                reference.Verify(CryptoProviderFactory.Default, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            XmlValidationException innerException = Assert.IsType<XmlValidationException>(error.InnerException);
            Assert.Contains("IDX30202", innerException.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void ReferenceVerify_UnsupportedDigest_ReturnsDigestFailure()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            reference.DigestMethod = "urn:unsupported-digest";

            // Act
            ValidationResult<Reference, ValidationError> result =
                reference.Verify(CryptoProviderFactory.Default, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            XmlValidationException innerException = Assert.IsType<XmlValidationException>(error.InnerException);
            Assert.Contains("IDX30208", innerException.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void ReferenceVerify_NullHashProvider_ReturnsDigestFailure()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { ReturnNullHashAlgorithm = true };

            // Act
            ValidationResult<Reference, ValidationError> result = reference.Verify(factory, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            XmlValidationException innerException = Assert.IsType<XmlValidationException>(error.InnerException);
            Assert.Contains("IDX30209", innerException.Message, StringComparison.Ordinal);
            Assert.Equal(1, factory.CreateHashAlgorithmCount);
            Assert.Equal(0, factory.ReleaseHashAlgorithmCount);
        }

        public static TheoryData<Exception> DigestComputationExceptions => new TheoryData<Exception>
        {
            new XmlValidationException("xml-validation-failed"),
            new XmlException("xml-failed"),
            new System.Xml.XmlException("system-xml-failed"),
            new CryptographicException("hash-failed"),
            new ArgumentException("invalid-hash-argument"),
            new InvalidOperationException("invalid-hash-provider"),
            new NotSupportedException("unsupported-hash")
        };

        [Theory, MemberData(nameof(DigestComputationExceptions), DisableDiscoveryEnumeration = true)]
        public void ReferenceVerify_HashProviderThrows_ReturnsDigestFailure(Exception exception)
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { HashCreationException = exception };

            // Act
            ValidationResult<Reference, ValidationError> result = reference.Verify(factory, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            Assert.Same(exception, error.InnerException);
            Assert.Equal(1, factory.CreateHashAlgorithmCount);
            Assert.Equal(0, factory.ReleaseHashAlgorithmCount);
        }

        [Fact]
        public void ReferenceVerify_HashingThrows_ReturnsDigestFailureAndReleasesHash()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            CryptographicException exception = new CryptographicException("hash-failed");
            ThrowingHashAlgorithm hashAlgorithm = new ThrowingHashAlgorithm(exception);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { HashAlgorithmOverride = hashAlgorithm };

            // Act
            ValidationResult<Reference, ValidationError> result = reference.Verify(factory, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            Assert.Same(exception, error.InnerException);
            Assert.Equal(1, factory.CreateHashAlgorithmCount);
            Assert.Equal(1, factory.ReleaseHashAlgorithmCount);
            Assert.True(hashAlgorithm.DisposeCalled);
        }

        [Fact]
        public void ReferenceVerify_UnexpectedHashingException_ThrowsAndReleasesHash()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            Exception exception = new Exception("unexpected-hash-failure");
            ThrowingHashAlgorithm hashAlgorithm = new ThrowingHashAlgorithm(exception);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { HashAlgorithmOverride = hashAlgorithm };

            // Act / Assert
            Assert.Same(exception, Assert.Throws<Exception>(() => reference.Verify(factory, new CallContext())));
            Assert.Equal(1, factory.ReleaseHashAlgorithmCount);
            Assert.True(hashAlgorithm.DisposeCalled);
        }

        [Fact]
        public void ReferenceVerify_HashProviderCancels_PropagatesCancellation()
        {
            // Arrange
            Reference reference = CreateFreshValidReference();
            OperationCanceledException exception = new OperationCanceledException();
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { HashCreationException = exception };

            // Act / Assert
            Assert.Same(exception, Assert.Throws<OperationCanceledException>(() => reference.Verify(factory, new CallContext())));
            Assert.Equal(0, factory.ReleaseHashAlgorithmCount);
        }

        [Fact]
        public void SignedInfoVerify_NullKey_ReturnsNullArgument()
        {
            // Arrange
            SignedInfo signedInfo = new SignedInfo();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signedInfo.Verify(null, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.NullArgument, result.Error.FailureType);
            Assert.Contains("key", result.Error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void SignedInfoVerify_NullFactory_ReturnsNullArgument()
        {
            // Arrange
            SignedInfo signedInfo = new SignedInfo();
            SecurityKey key = Default.AsymmetricSigningKey;

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signedInfo.Verify(key, null, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.NullArgument, result.Error.FailureType);
            Assert.Contains("cryptoProviderFactory", result.Error.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public void SignedInfoVerify_ValidReferences_ReturnsExactKey(int referenceCount)
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            SignedInfo signedInfo = new SignedInfo();
            for (int i = 0; i < referenceCount; i++)
                signedInfo.References.Add(CreateFreshValidReference());

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signedInfo.Verify(key, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            Assert.Same(key, result.Result);
            Assert.Null(result.Error);
        }

        [Fact]
        public void SignedInfoVerify_FirstReferenceFails_DoesNotProcessLaterReferences()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            SignedInfo signedInfo = new SignedInfo();
            Reference failing = CreateFreshValidReference();
            failing.DigestValue = Convert.ToBase64String(new byte[] { 9, 9, 9, 9 });
            signedInfo.References.Add(failing);
            signedInfo.References.Add(CreatePoisonReference());

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signedInfo.Verify(key, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, result.Error.FailureType);
            Assert.True(result.Error.StackFrames.Count >= 2);
        }

        [Fact]
        public void SignedInfoVerify_MiddleReferenceFails_DoesNotProcessLaterReferences()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            SignedInfo signedInfo = new SignedInfo();
            signedInfo.References.Add(CreateFreshValidReference());
            Reference failing = CreateFreshValidReference();
            failing.DigestValue = Convert.ToBase64String(new byte[] { 9, 9, 9, 9 });
            signedInfo.References.Add(failing);
            signedInfo.References.Add(CreatePoisonReference());

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signedInfo.Verify(key, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, result.Error.FailureType);
            Assert.True(result.Error.StackFrames.Count >= 2);
        }

        [Fact]
        public void SignatureVerify_NullKey_ReturnsNullArgument()
        {
            // Arrange
            Signature signature = new Signature();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(null, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.NullArgument, result.Error.FailureType);
            Assert.Contains("key", result.Error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void SignatureVerify_NullFactory_ReturnsNullArgument()
        {
            // Arrange
            Signature signature = new Signature();
            SecurityKey key = Default.AsymmetricSigningKey;

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, null, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.NullArgument, result.Error.FailureType);
            Assert.Contains("cryptoProviderFactory", result.Error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void SignatureVerify_NullSignedInfo_ReturnsSignedInfoNull()
        {
            // Arrange
            Signature signature = new Signature();
            SecurityKey key = Default.AsymmetricSigningKey;

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.IsType<SignatureValidationError>(result.Error);
            Assert.Equal(ValidationFailureType.SignedInfoNull, result.Error.FailureType);
            Assert.Contains("IDX30212", result.Error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void SignatureVerify_FactoryRejectsAlgorithm_DoesNotCreateProvider()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            Signature signature = new Signature(new SignedInfo { SignatureMethod = SecurityAlgorithms.RsaSha256Signature });
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { IsAlgorithmSupported = false };

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, factory, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.CryptoProviderFactoryDoesNotSupportAlgorithm, result.Error.FailureType);
            Assert.Contains("IDX30207", result.Error.Message, StringComparison.Ordinal);
            Assert.IsType<SecurityTokenValidationException>(result.Error.GetException());
            Assert.IsNotType<SecurityTokenInvalidSignatureException>(result.Error.GetException());
            Assert.Equal(0, factory.CreateForVerifyingCount);
        }

        [Fact]
        public void SignatureVerify_FactoryReturnsNullProvider()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            Signature signature = new Signature(new SignedInfo { SignatureMethod = SecurityAlgorithms.RsaSha256Signature })
            {
                SignatureValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })
            };
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { ReturnNullSignatureProvider = true };

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, factory, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(ValidationFailureType.CryptoProviderReturnedNull, result.Error.FailureType);
            Assert.Contains("IDX30203", result.Error.Message, StringComparison.Ordinal);
            Assert.Equal(1, factory.CreateForVerifyingCount);
            Assert.Equal(0, factory.ReleaseSignatureProviderCount);
        }

        [Fact]
        public void SignatureVerify_InvalidSignatureBytes_DoesNotValidateReferences()
        {
            // Arrange
            (Signature signature, SecurityKey key) = CreateValidSignedSignature();
            signature.SignatureValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, factory, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(SignatureValidationFailure.ValidationFailed, result.Error.FailureType);
            Assert.Contains("IDX10520", result.Error.Message, StringComparison.Ordinal);
            Assert.Contains("KeyId", result.Error.Message, StringComparison.Ordinal);
            Assert.IsType<SecurityTokenInvalidSignatureException>(result.Error.GetException());
            Assert.Equal(0, factory.CreateHashAlgorithmCount);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Fact]
        public void SignatureVerify_ValidSignatureTamperedPayload_ReturnsDigestFailure()
        {
            // Arrange
            SigningCredentials credentials = Default.AsymmetricSigningCredentials;
            string xml = CreateSignedXml(credentials, "issuer", Guid.NewGuid().ToString());
            xml = xml.Replace("entityID=\"issuer\"", "entityID=\"tampered\"");
            Signature signature = ReadSignature(xml);
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(credentials.Key, factory, new CallContext());

            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, result.Error.FailureType);
            Assert.True(result.Error.StackFrames.Count >= 2);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Fact]
        public void SignatureVerify_ValidSignatureAndReferences_ReturnsExactKey()
        {
            // Arrange
            (Signature signature, SecurityKey key) = CreateValidSignedSignature();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, CryptoProviderFactory.Default, new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            Assert.Same(key, result.Result);
            Assert.Null(result.Error);
        }

        [Fact]
        public void SignatureVerify_ReleasesProviderOnSuccess()
        {
            // Arrange
            (Signature signature, SecurityKey key) = CreateValidSignedSignature();
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory();

            // Act
            ValidationResult<SecurityKey, ValidationError> result =
                signature.Verify(key, factory, new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            Assert.Equal(1, factory.CreateForVerifyingCount);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Fact]
        public void SignatureVerify_ReleasesProviderWhenVerifyThrows()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            CustomSignatureProvider provider = new CustomSignatureProvider(key, SecurityAlgorithms.RsaSha256Signature)
            {
                ThrowOnVerify = new CryptographicException("verify-failed")
            };
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { SignatureProviderOverride = provider };
            Signature signature = new Signature(new SignedInfo { SignatureMethod = SecurityAlgorithms.RsaSha256Signature })
            {
                SignatureValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })
            };

            // Act / Assert
            Assert.Throws<CryptographicException>(() => signature.Verify(key, factory, new CallContext()));
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        [Fact]
        public void SignatureVerify_DigestComputationFails_ReturnsDigestErrorAndReleasesProvider()
        {
            // Arrange
            SecurityKey key = Default.AsymmetricSigningKey;
            CustomSignatureProvider provider = new CustomSignatureProvider(key, SecurityAlgorithms.RsaSha256Signature)
            {
                VerifyResult = true
            };
            TrackingCryptoProviderFactory factory = new TrackingCryptoProviderFactory { SignatureProviderOverride = provider };
            SignedInfo signedInfo = new SignedInfo { SignatureMethod = SecurityAlgorithms.RsaSha256Signature };
            signedInfo.References.Add(CreatePoisonReference());
            Signature signature = new Signature(signedInfo)
            {
                SignatureValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })
            };

            // Act
            ValidationResult<SecurityKey, ValidationError> result = signature.Verify(key, factory, new CallContext());

            // Assert
            SignatureValidationError error = AssertDigestComputationFailure(result);
            XmlValidationException innerException = Assert.IsType<XmlValidationException>(error.InnerException);
            Assert.Contains("IDX30202", innerException.Message, StringComparison.Ordinal);
            Assert.True(error.StackFrames.Count >= 3);
            Assert.Equal(1, factory.ReleaseSignatureProviderCount);
        }

        private static SignatureValidationError AssertDigestComputationFailure<TResult>(
            ValidationResult<TResult, ValidationError> result) where TResult : class
        {
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            SignatureValidationError error = Assert.IsType<SignatureValidationError>(result.Error);
            Assert.Equal(SignatureValidationFailure.ReferenceDigestValidationFailed, error.FailureType);
            Assert.Contains("IDX30201", error.Message, StringComparison.Ordinal);
            Assert.NotNull(error.InnerException);
            SecurityTokenInvalidSignatureException exception = Assert.IsType<SecurityTokenInvalidSignatureException>(error.GetException());
            Assert.Same(error.InnerException, exception.InnerException);
            return error;
        }

        private static (Signature Signature, SecurityKey Key) CreateValidSignedSignature()
        {
            SigningCredentials credentials = Default.AsymmetricSigningCredentials;
            string xml = CreateSignedXml(credentials, "issuer", Guid.NewGuid().ToString());
            return (ReadSignature(xml), credentials.Key);
        }

        private static Reference CreateFreshValidReference()
        {
            string xml = CreateSignedXml(Default.AsymmetricSigningCredentials, Guid.NewGuid().ToString(), Guid.NewGuid().ToString());
            return ReadSignature(xml).SignedInfo.References[0];
        }

        private static Reference CreatePoisonReference()
        {
            return new Reference
            {
                DigestMethod = SecurityAlgorithms.Sha256Digest,
                DigestValue = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })
            };
        }

        private static string CreateSignedXml(SigningCredentials credentials, string entityId, string referenceId)
        {
            using (MemoryStream buffer = new MemoryStream())
            {
                EnvelopedSignatureWriter writer = new EnvelopedSignatureWriter(XmlWriter.Create(buffer), credentials, referenceId);
                writer.WriteStartElement("EntityDescriptor", "urn:oasis:names:tc:SAML:2.0:metadata");
                writer.WriteAttributeString("entityID", entityId);
                writer.WriteEndElement();
                writer.Flush();
                return Encoding.UTF8.GetString(buffer.ToArray());
            }
        }

        private static Signature ReadSignature(string xml)
        {
            EnvelopedSignatureReader reader = new EnvelopedSignatureReader(XmlUtilities.CreateDictionaryReader(xml));
            while (reader.Read()) { }
            return reader.Signature;
        }

        private class TrackingCryptoProviderFactory : CryptoProviderFactory
        {
            public int CreateForVerifyingCount { get; private set; }
            public int ReleaseSignatureProviderCount { get; private set; }
            public int CreateHashAlgorithmCount { get; private set; }
            public int ReleaseHashAlgorithmCount { get; private set; }
            public bool IsAlgorithmSupported { get; set; } = true;
            public bool ReturnNullSignatureProvider { get; set; }
            public SignatureProvider SignatureProviderOverride { get; set; }
            public bool ReturnNullHashAlgorithm { get; set; }
            public HashAlgorithm HashAlgorithmOverride { get; set; }
            public Exception HashCreationException { get; set; }

            public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => IsAlgorithmSupported;

            public override bool IsSupportedAlgorithm(string algorithm) => true;

            public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
            {
                CreateForVerifyingCount++;
                if (ReturnNullSignatureProvider)
                    return null;
                if (SignatureProviderOverride != null)
                    return SignatureProviderOverride;
                return base.CreateForVerifying(key, algorithm);
            }

            public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
            {
                ReleaseSignatureProviderCount++;
                if (signatureProvider != null && SignatureProviderOverride == null)
                    base.ReleaseSignatureProvider(signatureProvider);
            }

            public override HashAlgorithm CreateHashAlgorithm(string algorithm)
            {
                CreateHashAlgorithmCount++;
                if (HashCreationException != null)
                    throw HashCreationException;
                if (ReturnNullHashAlgorithm)
                    return null;
                if (HashAlgorithmOverride != null)
                    return HashAlgorithmOverride;
                return base.CreateHashAlgorithm(algorithm);
            }

            public override void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm)
            {
                ReleaseHashAlgorithmCount++;
                if (hashAlgorithm != null)
                    base.ReleaseHashAlgorithm(hashAlgorithm);
            }
        }

        private sealed class ThrowingHashAlgorithm : SHA256
        {
            private readonly Exception _exception;

            public ThrowingHashAlgorithm(Exception exception)
            {
                _exception = exception;
            }

            public bool DisposeCalled { get; private set; }

            public override void Initialize() { }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) => throw _exception;

            protected override byte[] HashFinal() => throw _exception;

            protected override void Dispose(bool disposing)
            {
                DisposeCalled = true;
                base.Dispose(disposing);
            }
        }
    }
}
