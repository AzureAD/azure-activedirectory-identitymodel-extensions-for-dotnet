// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Selectors;
using System.ServiceModel.Description;

namespace System.ServiceModel.Federation
{
    /// <summary>
    /// These client credentials class that will serve up a SecurityTokenManager that will use a TrustChannel to get a token from an STS
    /// </summary>
    public class WsTrustChannelClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public WsTrustChannelClientCredentials()
            : base()
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            //SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The WSTrustChannelClientCredentials to create a copy of</param>
        protected WsTrustChannelClientCredentials(WsTrustChannelClientCredentials other)
            : base(other)
        {
        }

        protected override ClientCredentials CloneCore()
        {
            return new WsTrustChannelClientCredentials(this);
        }

        /// <summary>
        /// Extensibility point for serving up the WSTrustChannelSecurityTokenManager
        /// </summary>
        /// <returns>WSTrustChannelSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new WsTrustChannelSecurityTokenManager(this);
        }
    }
}
