// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite;

/// <summary>
/// An <see cref="ICryptoProvider"/> that creates <see cref="CompositeMLDsaSignatureProvider"/>
/// instances for composite ML-DSA algorithms. Wire this into Wilson:
/// <code>CryptoProviderFactory.Default.CustomCryptoProvider = new CompositeMLDsaCryptoProvider();</code>
/// </summary>
[Experimental("MSIDENT2001")]
public class CompositeMLDsaCryptoProvider : ICryptoProvider
{
    /// <inheritdoc/>
    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
    {
        if (!CompositeMLDsaAlgorithms.IsCompositeAlgorithm(algorithm))
            return false;

        // If a key is provided, it must be a CompositeMLDsaSecurityKey.
        if (args is not null && args.Length > 0 && args[0] is SecurityKey)
            return args[0] is CompositeMLDsaSecurityKey;

        return true;
    }

    /// <inheritdoc/>
    public object Create(string algorithm, params object[] args)
    {
        if (args is null || args.Length < 1 || args[0] is not CompositeMLDsaSecurityKey compositeKey)
            throw new ArgumentException(
                $"Expected {nameof(CompositeMLDsaSecurityKey)} as the first argument.");

        bool willCreateSignatures = args.Length > 1 && args[1] is bool b && b;

        return new CompositeMLDsaSignatureProvider(compositeKey, algorithm, willCreateSignatures);
    }

    /// <inheritdoc/>
    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposable)
            disposable.Dispose();
    }
}
