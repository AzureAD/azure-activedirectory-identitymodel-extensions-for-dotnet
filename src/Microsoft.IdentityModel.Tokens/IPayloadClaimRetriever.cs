// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an object capable of retrieving claims from a payload.
    /// </summary>
    public interface IPayloadClaimRetriever
    {
        /// <summary>
        /// Attempts to get a value from the payload.
        /// </summary>
        /// <param name="claimType">The claim type.</param>
        /// <param name="value">The value retrieved from the payload.</param>
        /// <returns><c>true</c> if the value could be found; otherwise <c>false</c></returns>
        public bool TryGetValue(string claimType, out object value);

        /// <summary>
        /// Gets a value from the payload as a string.
        /// </summary>
        /// <param name="claimType">The claim type.</param>
        /// <returns>The value from the payload or an empty string if not found.</returns>
        public string GetStringValue(string claimType);

        /// <summary>
        /// Gets a value from the payload as a DateTime.
        /// </summary>
        /// <param name="claimType">The claim type.</param>
        /// <returns>The value from the payload or the minimum value of DateTime if not found.</returns>
        public DateTime GetDateTimeValue(string claimType);

        /// <summary>
        /// Gets a value from the payload as a collection of strings.
        /// </summary>
        /// <param name="claimType">The claim type.</param>
        /// <returns>The value from the payload or an empty list if not found.</returns>
        public IList<string> GetStringCollection(string claimType);
    }
}
