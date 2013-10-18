//-----------------------------------------------------------------------
// <copyright file="TextStrings.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
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

namespace System.IdentityModel
{
    using System.Diagnostics.CodeAnalysis;

    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    internal static class TextStrings
    {
        public const string Empty = "empty";
        public const string Null  = "null";
        public const string ValidationParameters = "validationParameters";
        public const string MaximumTokenSize = "maximumTokenSize";
        public const string Comment   = "Element below commented by: ValidatingIssuerNameRegistry.WriteToConfg on: '{0} (UTC)'. Differences were found in the Metatdata from: '{1}'.";
    }
}
