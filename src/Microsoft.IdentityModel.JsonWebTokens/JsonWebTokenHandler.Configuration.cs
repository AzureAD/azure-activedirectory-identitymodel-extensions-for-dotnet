// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Contains configuration settings for JWT handler.
    /// </summary>
    /// <remarks>
    /// The JsonWebTokenHandlerConfiguration class allows applications to customize token processing
    /// behavior application-wide, including settings like actor token chain depth limitations.
    /// This helps prevent security issues like excessive recursion and denial of service attacks.
    /// </remarks>
    public static class JsonWebTokenHandlerConfiguration
    {
        // Default value
        private static int s_maxActorChainLength = 5;

        /// <summary>
        /// Gets or sets the maximum depth allowed when processing nested actor tokens.
        /// This prevents excessive recursion when handling deeply nested actor tokens.
        /// The value must be at least 0. Value 0 would mean that the actor token is not allowed to be nested.
        /// Default value is 5.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if the value is less than 0.</exception>
        public static int MaxActorChainLength
        {
            get => s_maxActorChainLength;
            set
            {
                if (value < 0)
                    throw LogHelper.LogExceptionMessage(
                        new ArgumentOutOfRangeException(nameof(value),
                            LogHelper.FormatInvariant("IDX14314: MaxActorChainLength must be non negative. Value provided: {0}", value)));

                s_maxActorChainLength = value;
            }
        }
    }
}
