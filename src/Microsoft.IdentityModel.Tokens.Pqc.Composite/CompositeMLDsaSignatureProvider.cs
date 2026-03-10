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
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="algorithm"/> is not a recognised composite ML-DSA algorithm,
    /// or if the algorithm does not match the key's <see cref="CompositeMLDsa.Algorithm"/>.
    /// </exception>
    public CompositeMLDsaSignatureProvider(
        CompositeMLDsaSecurityKey key,
        string algorithm,
        bool willCreateSignatures)
        : base(key, algorithm)
    {
        if (key is null)
            throw LogHelper.LogArgumentNullException(nameof(key));

        if (!CompositeMLDsaAlgorithms.IsCompositeAlgorithm(algorithm))
            throw LogHelper.LogExceptionMessage(
                new ArgumentException($"Algorithm '{algorithm}' is not a recognised composite ML-DSA algorithm.", nameof(algorithm)));

        // Validate that the JOSE algorithm matches the key's underlying algorithm.
        CompositeMLDsaAlgorithm expectedDotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        if (key.CompositeMLDsa.Algorithm != expectedDotNetAlg)
            throw LogHelper.LogExceptionMessage(
                new ArgumentException(
                    $"Algorithm mismatch: JOSE algorithm '{algorithm}' requires {expectedDotNetAlg} but the key uses {key.CompositeMLDsa.Algorithm}.",
                    nameof(algorithm)));

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

        if (offset < 0)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be non-negative."));

        if (count < 1)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(count), count, "Count must be at least 1."));

        if (offset + count > input.Length)
            throw LogHelper.LogExceptionMessage(
                new ArgumentException($"offset ({offset}) + count ({count}) exceeds input length ({input.Length})."));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] data = new byte[count];
        try
        {
            Array.Copy(input, offset, data, 0, count);
            return _compositeMLDsa.SignData(data);
        }
        finally
        {
            Array.Clear(data, 0, data.Length);
        }
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

        if (inputOffset < 0)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset, "Input offset must be non-negative."));

        if (inputLength < 1)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(inputLength), inputLength, "Input length must be at least 1."));

        if (inputOffset + inputLength > input.Length)
            throw LogHelper.LogExceptionMessage(
                new ArgumentException($"inputOffset ({inputOffset}) + inputLength ({inputLength}) exceeds input length ({input.Length})."));

        if (signatureOffset < 0)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(signatureOffset), signatureOffset, "Signature offset must be non-negative."));

        if (signatureLength < 1)
            throw LogHelper.LogExceptionMessage(
                new ArgumentOutOfRangeException(nameof(signatureLength), signatureLength, "Signature length must be at least 1."));

        if (signatureOffset + signatureLength > signature.Length)
            throw LogHelper.LogExceptionMessage(
                new ArgumentException($"signatureOffset ({signatureOffset}) + signatureLength ({signatureLength}) exceeds signature length ({signature.Length})."));

        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] data = new byte[inputLength];
        byte[] sig = new byte[signatureLength];
        try
        {
            Array.Copy(input, inputOffset, data, 0, inputLength);
            Array.Copy(signature, signatureOffset, sig, 0, signatureLength);
            return _compositeMLDsa.VerifyData(data, sig);
        }
        finally
        {
            Array.Clear(data, 0, data.Length);
            Array.Clear(sig, 0, sig.Length);
        }
    }

#if NET6_0_OR_GREATER
    /// <inheritdoc/>
    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        byte[] sig = _compositeMLDsa.SignData(data.ToArray());
        try
        {
            if (sig.Length > destination.Length)
            {
                bytesWritten = 0;
                return false;
            }

            sig.CopyTo(destination);
            bytesWritten = sig.Length;

            return true;
        }
        finally
        {
            Array.Clear(sig, 0, sig.Length);
        }
    }
#endif

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
