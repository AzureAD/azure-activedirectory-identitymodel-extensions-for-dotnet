// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains results of a single step in validating a <see cref="SecurityToken"/>.
    /// A <see cref="TokenValidationResult"/> maintains a list of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class ValidationResult
    {
        /// <summary>
        /// Creates an instance of <see cref="ValidationResult"/>
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="tokenHandler">The <see cref="TokenHandler"/> that is being used to validate the token.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        internal ValidationResult(
            SecurityToken securityToken,
            TokenHandler tokenHandler,
            ValidationParameters validationParameters)
        {
            TokenHandler = tokenHandler ?? throw new ArgumentNullException("TokenHandler cannot be null.");
            SecurityToken = securityToken ?? throw new ArgumentNullException("SecurityToken cannot be null.");
            ValidationParameters = validationParameters ?? throw new ArgumentNullException("ValidationParameters cannot be null."); ;
        }

        /// <summary>
        /// Logs the validation result.
        /// </summary>
#pragma warning disable CA1822 // Mark members as static
        public void Log()
#pragma warning restore CA1822 // Mark members as static
        {
            // TODO - Do we need this, how will it work?
        }

        public SecurityToken SecurityToken { get; private set; }

        public TokenHandler TokenHandler { get; private set; }

        public ValidationParameters ValidationParameters { get; private set; }

        #region Validation Results
        public ValidationResult? ActorValidationResult { get; internal set; }
        public string? ValidatedAudience { get; internal set; }
        public ValidatedIssuer? ValidatedIssuer { get; internal set; }
        public ValidatedLifetime? ValidatedLifetime { get; internal set; }
        public DateTime? ValidatedTokenReplayExpirationTime { get; internal set; }
        public ValidatedTokenType? ValidatedTokenType { get; internal set; }
        public SecurityKey? ValidatedSigningKey { get; internal set; }
        public ValidatedSigningKeyLifetime? ValidatedSigningKeyLifetime { get; internal set; }
        #endregion

        #region Claims
        // Fields lazily initialized in a thread-safe manner. _claimsIdentity is protected by the _claimsIdentitySyncObj
        // lock, and since null is a valid initialized value, _claimsIdentityInitialized tracks whether or not it's valid.
        // _claims is constructed by reading the data from the ClaimsIdentity and is synchronized using Interlockeds
        // to ensure only one dictionary is published in the face of concurrent access (but if there's a race condition,
        // multiple dictionaries could be constructed, with only one published for all to see). Simiarly, _propertyBag
        // is initalized with Interlocked to ensure only a single instance is published in the face of concurrent use.
        // _claimsIdentityInitialized only ever transitions from false to true, and is volatile to reads/writes are not
        // reordered relative to the other operations. The rest of the objects are not because the .NET memory model
        // guarantees object writes are store releases and that reads won't be introduced.
        private volatile bool _claimsIdentityInitialized;
        private object? _claimsIdentitySyncObj;
        private ClaimsIdentity? _claimsIdentity;
        private Dictionary<string, object>? _claims;

        /// <summary>
        /// The <see cref="Dictionary{String, Object}"/> created from the validated security token.
        /// </summary>
        public IDictionary<string, object> Claims
        {
            get
            {
                if (_claims is null)
                {
                    Interlocked.CompareExchange(ref _claims, TokenUtilities.CreateDictionaryFromClaims(ClaimsIdentity.Claims), null);
                }

                return _claims;
            }
        }

        /// <summary>
        /// The <see cref="ClaimsIdentity"/> created from the validated security token.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity
        {
            get
            {
                if (!_claimsIdentityInitialized)
                {
                    lock (ClaimsIdentitySyncObj)
                    {
                        return ClaimsIdentityNoLocking;
                    }
                }

                return _claimsIdentity!;
            }
            set
            {
                if (value is null)
                    throw new ArgumentNullException(nameof(value), "ClaimsIdentity cannot be set as null.");

                lock (ClaimsIdentitySyncObj)
                {
                    ClaimsIdentityNoLocking = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="_claimsIdentity"/> without synchronization. All accesses must either
        /// be protected or used when the caller knows access is serialized.
        /// </summary>
        internal ClaimsIdentity ClaimsIdentityNoLocking
        {
            get
            {
                if (!_claimsIdentityInitialized)
                {
                    Debug.Assert(_claimsIdentity is null);

                    _claimsIdentity = TokenHandler.CreateClaimsIdentityInternal(SecurityToken, ValidationParameters, ValidatedIssuer?.Issuer);
                    _claimsIdentityInitialized = true;
                }

                return _claimsIdentity!;
            }
            set
            {
                Debug.Assert(value is not null);
                _claimsIdentity = value;
                _claims = null;
                _claimsIdentityInitialized = true;
            }
        }

        /// <summary>Gets the object to use in <see cref="ClaimsIdentity"/> for double-checked locking.</summary>
        private object ClaimsIdentitySyncObj
        {
            get
            {
                object? syncObj = _claimsIdentitySyncObj;
                if (syncObj is null)
                {
                    Interlocked.CompareExchange(ref _claimsIdentitySyncObj, new object(), null);
                    syncObj = _claimsIdentitySyncObj;
                }

                return syncObj;
            }
        }
        #endregion
    }
}
#nullable disable
