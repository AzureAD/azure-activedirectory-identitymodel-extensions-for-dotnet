//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the IssuerSerial property of X509Data as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    public class IssuerSerial
    {
        /// <summary>
        /// Gets the IssuerName of the IssuerSerial.
        /// </summary>
        public string IssuerName { get; }

        /// <summary>
        /// Gets the SerialNumber of the IssuerSerial.
        /// </summary>
        public string SerialNumber { get; }

        /// <summary>
        /// Creates an IssuerSerial using the specified IssuerName and SerialNumber.
        /// </summary>
        public IssuerSerial(string issuerName, string serialNumber)
        {
            IssuerName = issuerName;
            SerialNumber = serialNumber;
        }

        /// <summary>
        /// Compares two IssuerSerial objects.
        /// </summary>
        public override bool Equals(object obj)
        {
            var other = obj as IssuerSerial;
            if (other == null)
                return false;
            else if (string.Compare(IssuerName, other.IssuerName, StringComparison.OrdinalIgnoreCase) != 0
                || string.Compare(SerialNumber, other.SerialNumber, StringComparison.OrdinalIgnoreCase) != 0)
                return false;
            return true;
        }

        /// <summary>
        /// Serves as a hash function for IssuerSerial.
        /// </summary>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

    }
}