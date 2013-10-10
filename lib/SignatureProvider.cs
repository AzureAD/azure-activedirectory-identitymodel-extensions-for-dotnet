//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Globalization;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// This class defines the object model for types that provide signature services.
    /// </summary>
    public abstract class SignatureProvider : IDisposable
    {
        /// <summary>
        /// Can be over written in descendants to dispose of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>     
        protected virtual void Dispose( bool disposing )
        {
        }

        /// <summary>
        /// Produces a signature over the 'input'
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <returns>signed bytes</returns>
        public abstract byte[] Sign( byte[] input );

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public abstract bool Verify( byte[] input, byte[] signature );

        /// <summary>
        /// Gets or sets a user context for a <see cref="SignatureProvider"/>.
        /// </summary>
        public string Context
        {
            set;
            get;
        }

        #region IDisposable Members

        /// <summary>
        /// Implement in derived derived class for resource cleanup.
        /// </summary>
        public abstract void Dispose();

        #endregion
    }
}

