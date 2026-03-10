// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite;

/// <summary>
/// Provides composite ML-DSA signing and verification by delegating to
/// the atomic <see cref="CompositeMLDsa"/> SignData and VerifyData methods.
/// </summary>
[Experimental("MSIDENT2001")]
public class CompositeMLDsaSignatureProvider : SignatureProvider
{
    private readonly CompositeMLDsa _compositeMLDsa;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of <see cref="CompositeMLDsaSignatureProvider"/>.
    /// </summary>
    /// <param name="key">The composite ML-DSA security key.</param>
    /// <param name="algorithm">The JOSE algorithm identifier.</param>
    /// <param name="willCreateSignatures">
    /// <c>true</c> if this provider will be used for signing; <c>false</c> for verification.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
    public CompositeMLDsaSignatureProvider(
        CompositeMLDsaSecurityKey key,
        string algorithm,
        bool willCreateSignatures)
        : base(key, algorithm)
    {
        if (key is null)
            throw LogHelper.LogArgumentNullException(nameof(key));

        _compositeMLDsa = key.CompositeMLDsa;
        WillCreateSignatures = willCreateSignatures;
    }

    /// <inheritdoc/>
    public override byte[] Sign(byte[] input)
    {
        if (input is null || input.Length == 0)
            throw LogHelper.LogArgumentNullException(nameof(input));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        return _compositeMLDsa.SignData(input);
    }

    /// <inheritdoc/>
    public override byte[] Sign(byte[] input, int offset, int count)
    {
        if (input is null || input.Length == 0)
            throw LogHelper.LogArgumentNullException(nameof(input));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] data = new byte[count];
        Array.Copy(input, offset, data, 0, count);

        return _compositeMLDsa.SignData(data);
    }

    /// <inheritdoc/>
    public override bool Verify(byte[] input, byte[] signature)
    {
        if (input is null || input.Length == 0)
            throw LogHelper.LogArgumentNullException(nameof(input));

        if (signature is null || signature.Length == 0)
            throw LogHelper.LogArgumentNullException(nameof(signature));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        return _compositeMLDsa.VerifyData(input, signature);
    }

    /// <inheritdoc/>
    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        if (input is null)
            throw LogHelper.LogArgumentNullException(nameof(input));

        if (signature is null)
            throw LogHelper.LogArgumentNullException(nameof(signature));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] data = new byte[inputLength];
        Array.Copy(input, inputOffset, data, 0, inputLength);

        byte[] sig = new byte[signatureLength];
        Array.Copy(signature, signatureOffset, sig, 0, signatureLength);

        return _compositeMLDsa.VerifyData(data, sig);
    }

#if NET6_0_OR_GREATER
    /// <inheritdoc/>
    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] sig = _compositeMLDsa.SignData(data.ToArray());
        if (sig.Length > destination.Length)
        {
            bytesWritten = 0;
            return false;
        }

        sig.CopyTo(destination);
        bytesWritten = sig.Length;

        return true;
    }
#endif

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
