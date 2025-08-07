// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable RS0016 // Add public types and members to the declared API

    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-05.html
    /// </summary>
    public static partial class JsonWebAlgorithmsKeyTypes
    {
#pragma warning disable 1591
        public const string MLDSA = "AKP";
#pragma warning restore 1591
    }
}
