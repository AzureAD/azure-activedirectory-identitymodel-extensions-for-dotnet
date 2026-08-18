// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;

#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// A <see cref="FactAttribute"/> that skips the test when the specified Composite ML-DSA
    /// algorithm is not supported on the current platform.
    /// </summary>
    public sealed class CompositeMLDsaFactAttribute : FactAttribute
    {
        public CompositeMLDsaFactAttribute(string algorithm)
        {
            if (!CompositeMLDsa.IsSupported)
            {
                Skip = "Composite ML-DSA is not supported on this platform.";
                return;
            }

            var bcl = CompositeMLDsaKeyingMaterial.GetCompositeMLDsaAlgorithmOrNull(algorithm);
            if (bcl == null || !CompositeMLDsa.IsAlgorithmSupported(bcl))
                Skip = $"Composite ML-DSA algorithm '{algorithm}' is not supported on this platform.";
        }
    }

    /// <summary>
    /// A <see cref="TheoryAttribute"/> that skips the test when the specified Composite ML-DSA
    /// algorithm is not supported on the current platform.
    /// </summary>
    public sealed class CompositeMLDsaTheoryAttribute : TheoryAttribute
    {
        public CompositeMLDsaTheoryAttribute(string algorithm)
        {
            if (!CompositeMLDsa.IsSupported)
            {
                Skip = "Composite ML-DSA is not supported on this platform.";
                return;
            }

            var bcl = CompositeMLDsaKeyingMaterial.GetCompositeMLDsaAlgorithmOrNull(algorithm);
            if (bcl == null || !CompositeMLDsa.IsAlgorithmSupported(bcl))
                Skip = $"Composite ML-DSA algorithm '{algorithm}' is not supported on this platform.";
        }
    }
}
