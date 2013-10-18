//-----------------------------------------------------------------------
// <copyright file="WSSecurityUtilityConstants.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
// <license>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </license>

namespace System.IdentityModel.Tokens
{
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    /// Defines constants needed from WS-SecureUtility standard schema.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    internal static class WSSecurityUtilityConstants
    {
#pragma warning disable 1591
        public const string Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        public const string Prefix    = "wsu";

        public static class Attributes
        {
            public const string Id = "Id";
        }
#pragma warning restore 1591
    }
}
