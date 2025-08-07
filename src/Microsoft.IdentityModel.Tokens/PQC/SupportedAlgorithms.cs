// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines the default set of algorithms this library supports
    /// </summary>
    internal static partial class SupportedAlgorithms
    {
        internal static readonly ICollection<string> MldsaSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.Mldsa44,
        };

        internal static bool IsSupportedMldsaAlgorithm(string algorithm)
        {
            return MldsaSigningAlgorithms.Contains(algorithm);
        }
    }
}
