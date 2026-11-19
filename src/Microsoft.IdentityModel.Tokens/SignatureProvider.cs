// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signature services, signing and verifying.
    /// </summary>
    public abstract class SignatureProvider : IDisposable
    {
        /// <summary>
        /// Maintains the number of external references
        /// see: <see cref="AddRef"/>, <see cref="RefCount"/>, <see cref="Release"/>
        /// </summary>
        private int _referenceCount;
        private int _disposeClaimed;
        private CryptoProviderCache _cryptoProviderCache;
        private const int Retired = int.MinValue;
        private const int ReferenceCountMask = int.MaxValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to be used.</param>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="algorithm"/> is null or empty.</exception>
        protected SignatureProvider(SecurityKey key, string algorithm)
        {
            Key = key ?? throw LogHelper.LogArgumentNullException(nameof(key));
            Algorithm = (string.IsNullOrEmpty(algorithm)) ? throw LogHelper.LogArgumentNullException(nameof(algorithm)) : algorithm;
            _referenceCount = 1;
        }

        internal int AddRef()
        {
            return TryAddRef() ? RefCount : 0;
        }

        internal bool TryAddRef()
        {
            int state;
            while ((state = Volatile.Read(ref _referenceCount)) >= 0 && state < ReferenceCountMask)
            {
                if (Interlocked.CompareExchange(ref _referenceCount, state + 1, state) == state)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="SignatureProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This is for use by the application and not used by this SDK.</remarks>
        public string Context { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="CryptoProviderCache"/> that is associated with this <see cref="SignatureProvider"/>
        /// </summary>
        public CryptoProviderCache CryptoProviderCache
        {
            get => Volatile.Read(ref _cryptoProviderCache);
            set => Volatile.Write(ref _cryptoProviderCache, value);
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Can be over written in descendants to dispose of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>
        protected abstract void Dispose(bool disposing);

        internal bool IsCached { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>.
        /// </summary>
        public SecurityKey Key { get; private set; }

        /// <summary>
        /// For testing purposes
        /// </summary>
        internal virtual int ObjectPoolSize => 0;

        internal int RefCount => Volatile.Read(ref _referenceCount) & ReferenceCountMask;

        internal int Release()
        {
            int state;
            while (((state = Volatile.Read(ref _referenceCount)) & ReferenceCountMask) > 0)
            {
                if (Interlocked.CompareExchange(ref _referenceCount, state - 1, state) == state)
                {
                    DisposeIfRetiredAndUnused();
                    return (state - 1) & ReferenceCountMask;
                }
            }

            return 0;
        }

        internal bool TrySetCache(CryptoProviderCache cache)
        {
            if (Interlocked.CompareExchange(ref _cryptoProviderCache, cache, null) != null)
                return false;

            // Check after claiming ownership so a stale pre-retirement observation cannot admit the provider.
            if (Volatile.Read(ref _referenceCount) < 0)
            {
                Interlocked.CompareExchange(ref _cryptoProviderCache, null, cache);
                return false;
            }

            IsCached = true;
            return true;
        }

        internal void RemoveCacheOwnership(CryptoProviderCache cache)
        {
            if (ReferenceEquals(Volatile.Read(ref _cryptoProviderCache), cache))
            {
                // Reset the unpublished flag before another cache can claim ownership.
                IsCached = false;
                Interlocked.CompareExchange(ref _cryptoProviderCache, null, cache);
            }
        }

        internal void Retire()
        {
            // Retirement and acquisition share one atomic state, so a last release cannot race a new borrower.
            int state;
            do
            {
                state = Volatile.Read(ref _referenceCount);
            }
            while (Interlocked.CompareExchange(ref _referenceCount, state | Retired, state) != state);

            CryptoProviderCache = null;
            DisposeIfRetiredAndUnused();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Custom disposal failures must not block other providers or escape final release.")]
        private void DisposeIfRetiredAndUnused()
        {
            if (Volatile.Read(ref _referenceCount) != Retired ||
                Interlocked.CompareExchange(ref _disposeClaimed, 1, 0) != 0)
                return;

            try
            {
                Dispose();
            }
            catch (Exception ex)
            {
                // A custom provider must not prevent retirement of other providers, or be disposed twice after throwing.
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10726, ex));
            }
        }

        /// <summary>
        /// This must be overridden to produce a signature over the 'input'.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <returns>signed bytes</returns>
        public abstract byte[] Sign(byte[] input);

        /// <summary>
        /// Produces a signature over the specified region of the <paramref name="input"/>.
        /// </summary>
        /// <param name="input">The bytes to produce a signature over.</param>
        /// <param name="offset">The offset to specify the beginning of the region.</param>
        /// <param name="count">The count to specify the end of the region.</param>
        /// <returns>The signature bytes.</returns>
        public virtual byte[] Sign(byte[] input, int offset, int count)
        {
            throw LogHelper.LogExceptionMessage(
                new NotImplementedException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX10267,
                        LogHelper.MarkAsNonPII("public virtual byte[] Sign(byte[] input, int offset, int count)"),
                        LogHelper.MarkAsNonPII(GetType().FullName))));

        }

#if NET6_0_OR_GREATER
        /// <summary>
        /// Produces a signature over the <paramref name="data"/> and writes it to <paramref name="destination"/>.
        /// </summary>
        /// <param name="data">The bytes to produce a signature over.</param>
        /// <param name="destination">The pre-allocated span where signature bytes will be placed.</param>
        /// <param name="bytesWritten">The number of bytes written into the signature span.</param>         
        /// <returns>returns <see langword="true"/> if creation of signature succeeded, <see langword="false"/> otherwise.</returns>
        public virtual bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            throw LogHelper.LogExceptionMessage(
                new NotImplementedException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX10267,
                        LogHelper.MarkAsNonPII("public virtual bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)"),
                        LogHelper.MarkAsNonPII(GetType().FullName))));
        }
#endif
        /// <summary>
        /// Verifies that the <paramref name="signature"/> over <paramref name="input"/> using the
        /// <see cref="SecurityKey"/> and <see cref="SignatureProvider.Algorithm"/> specified by this
        /// <see cref="SignatureProvider"/> are consistent.
        /// </summary>
        /// <param name="input">the bytes that were signed.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public abstract bool Verify(byte[] input, byte[] signature);

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature. Using <see cref="SecurityKey"/> and 'algorithm' passed to <see cref="SignatureProvider( SecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to verify.</param>
        /// <param name="inputOffset">offset in to input bytes to calculate hash.</param>
        /// <param name="inputLength">number of bytes of signature to use.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <param name="signatureOffset">offset into signature array.</param>
        /// <param name="signatureLength">how many bytes to verify.</param>
        /// <returns>true if computed signature matches the signature parameter, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0. </exception>
        /// <exception cref="ArgumentException">'length &lt; 1'</exception>
        /// <exception cref="ArgumentException">'offset + length &gt; input.Length'</exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        public virtual bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
        {
            throw LogHelper.LogExceptionMessage(
                new NotImplementedException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX10267,
                        LogHelper.MarkAsNonPII("public virtual bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)"),
                        LogHelper.MarkAsNonPII(GetType().FullName))));
        }

        /// <summary>
        /// Gets or sets a bool indicating if this <see cref="SignatureProvider"/> is expected to create signatures.
        /// </summary>
        public bool WillCreateSignatures { get; protected set; }
    }
}
