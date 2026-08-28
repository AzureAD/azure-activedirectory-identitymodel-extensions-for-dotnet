// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    /// <summary>
    /// Exact-value tests pinning the WS-Trust constant URIs.
    /// </summary>
    /// <remarks>
    /// These assertions are deliberately literal. The constants are wire values consumed by
    /// interoperating stacks, so a change to any of them is a breaking protocol change and
    /// must be a conscious decision rather than an incidental edit.
    ///
    /// A note on WS-Trust 1.4, because it reads like a mistake and has been "corrected" before:
    /// 1.4 is an addendum to 1.3. Its schema declares
    /// targetNamespace='http://docs.oasis-open.org/ws-sx/ws-trust/200802' but imports the core
    /// types with xmlns:wst='http://docs.oasis-open.org/ws-sx/ws-trust/200512', and defines only
    /// the interactive challenge additions. It contains no BinarySecretTypeEnum, no key types and
    /// no actions of its own. Consequently 200802 identifies the 1.4 element namespace only, while
    /// the BinarySecret/@Type, KeyType and action URIs all remain at 200512.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust-1.4.xsd
    /// </remarks>
    public class WsTrustConstantsTests
    {
        private const string Feb2005Prefix = "http://schemas.xmlsoap.org/ws/2005/02/trust/";
        private const string Trust200512Prefix = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";
        private const string Trust200802Prefix = "http://docs.oasis-open.org/ws-sx/ws-trust/200802/";

        [Fact]
        public void WsTrustFeb2005BinarySecretTypes_HaveExpectedValues()
        {
            // Arrange
            var binarySecretTypes = WsTrustBinarySecretTypes.TrustFeb2005;

            // Act & Assert
            Assert.Equal("http://schemas.xmlsoap.org/ws/2005/02/trust/AsymmetricKey", binarySecretTypes.AsymmetricKey);
            Assert.Equal("http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", binarySecretTypes.Nonce);
            Assert.Equal("http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey", binarySecretTypes.SymmetricKey);
        }

        [Fact]
        public void WsTrust13BinarySecretTypes_HaveExpectedValues()
        {
            // Arrange
            var binarySecretTypes = WsTrustBinarySecretTypes.Trust13;

            // Act & Assert
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey", binarySecretTypes.AsymmetricKey);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce", binarySecretTypes.Nonce);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey", binarySecretTypes.SymmetricKey);
        }

        [Fact]
        public void WsTrust14BinarySecretTypes_HaveExpectedValues()
        {
            // Arrange
            var binarySecretTypes = WsTrustBinarySecretTypes.Trust14;

            // Act & Assert
            // 1.4 inherits these from 1.3, so the values are the 200512 ones. See the class remarks.
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey", binarySecretTypes.AsymmetricKey);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce", binarySecretTypes.Nonce);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey", binarySecretTypes.SymmetricKey);
        }

        [Fact]
        public void WsTrust13And14BinarySecretTypes_AreIdentical()
        {
            // Arrange
            var trust13 = WsTrustBinarySecretTypes.Trust13;
            var trust14 = WsTrustBinarySecretTypes.Trust14;

            // Act & Assert
            Assert.Equal(trust13.AsymmetricKey, trust14.AsymmetricKey);
            Assert.Equal(trust13.Nonce, trust14.Nonce);
            Assert.Equal(trust13.SymmetricKey, trust14.SymmetricKey);
        }

        [Fact]
        public void WsTrust14BinarySecretTypes_AsymmetricKey_IsNotAKeyType()
        {
            // Arrange
            // Regression: 6.8.0 shipped WsTrust14BinarySecretTypes.AsymmetricKey holding the
            // Bearer *KeyType* URI, which is a different constant family entirely.
            var binarySecretTypes = WsTrustBinarySecretTypes.Trust14;

            // Act & Assert
            Assert.NotEqual(WsTrustKeyTypes.Trust14.Bearer, binarySecretTypes.AsymmetricKey);
            Assert.EndsWith("/AsymmetricKey", binarySecretTypes.AsymmetricKey, System.StringComparison.Ordinal);
        }

        [Fact]
        public void BinarySecretTypes_DoNotUseThe200802Namespace()
        {
            // Arrange
            // 200802 is the 1.4 element namespace only; no BinarySecret/@Type value lives there.
            var allValues = new[]
            {
                WsTrustBinarySecretTypes.TrustFeb2005.AsymmetricKey,
                WsTrustBinarySecretTypes.TrustFeb2005.Nonce,
                WsTrustBinarySecretTypes.TrustFeb2005.SymmetricKey,
                WsTrustBinarySecretTypes.Trust13.AsymmetricKey,
                WsTrustBinarySecretTypes.Trust13.Nonce,
                WsTrustBinarySecretTypes.Trust13.SymmetricKey,
                WsTrustBinarySecretTypes.Trust14.AsymmetricKey,
                WsTrustBinarySecretTypes.Trust14.Nonce,
                WsTrustBinarySecretTypes.Trust14.SymmetricKey
            };

            // Act & Assert
            foreach (var value in allValues)
            {
                Assert.DoesNotContain(Trust200802Prefix, value, System.StringComparison.Ordinal);
            }
        }

        [Fact]
        public void WsTrust14KeyTypes_UseThe200512Namespace()
        {
            // Arrange
            var keyTypes = WsTrustKeyTypes.Trust14;

            // Act & Assert
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer", keyTypes.Bearer);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1", keyTypes.PSHA1);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey", keyTypes.PublicKey);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey", keyTypes.Symmetric);
        }

        [Fact]
        public void WsTrust14Actions_UseThe200512Namespace()
        {
            // Arrange
            var actions = WsTrustActions.Trust14;

            // Act & Assert
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue", actions.IssueRequest);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal", actions.IssueFinal);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel", actions.Cancel);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew", actions.Renew);
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate", actions.Validate);
        }

        [Fact]
        public void WsTrust14Constants_UseThe200802ElementNamespace()
        {
            // Arrange
            // The element namespace is the one place 200802 is correct.
            var constants = WsTrustConstants.Trust14;

            // Act & Assert
            Assert.Equal("http://docs.oasis-open.org/ws-sx/ws-trust/200802", constants.Namespace);
        }

        [Fact]
        public void WsTrustVersions_UseDistinctBinarySecretNamespaces()
        {
            // Arrange
            var feb2005 = WsTrustBinarySecretTypes.TrustFeb2005;
            var trust13 = WsTrustBinarySecretTypes.Trust13;

            // Act & Assert
            Assert.StartsWith(Feb2005Prefix, feb2005.SymmetricKey, System.StringComparison.Ordinal);
            Assert.StartsWith(Trust200512Prefix, trust13.SymmetricKey, System.StringComparison.Ordinal);
            Assert.NotEqual(feb2005.SymmetricKey, trust13.SymmetricKey);
        }
    }
}
