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

using System.Collections.Generic;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
    public static class DSigXmlComparer
    {
        public static void GetDiffs(KeyInfo keyInfo1, KeyInfo keyInfo2,  List<string> diffs)
        {
            if (keyInfo1 == null && keyInfo2 == null)
                return;

            if (keyInfo1 == null && keyInfo2 != null)
                diffs.Add($" keyInfo1 == null && keyInfo2 != null");

            if (keyInfo1 != null && keyInfo2 == null)
                diffs.Add($" keyInfo1 != null && reference2 == null");

            string retVal = string.Empty;
            if (!IdentityComparer.AreStringsEqual(keyInfo1.CertificateData, keyInfo2.CertificateData))
                diffs.Add($" KeyInfo.CertificateData: {keyInfo1.CertificateData}, {keyInfo2.CertificateData}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.IssuerName, keyInfo2.IssuerName))
                diffs.Add($" KeyInfo.IssuerName: {keyInfo1.IssuerName}, {keyInfo2.IssuerName}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.Kid, keyInfo2.Kid))
                diffs.Add($" KeyInfo.Kid: {keyInfo1.Kid}, {keyInfo2.Kid}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.RetrievalMethodUri, keyInfo2.RetrievalMethodUri))
                diffs.Add($" KeyInfo.RetrievalMethodUri: {keyInfo1.RetrievalMethodUri}, {keyInfo2.RetrievalMethodUri}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SerialNumber, keyInfo2.SerialNumber))
                diffs.Add($" KeyInfo.SerialNumber: '{keyInfo1.SerialNumber}', '{keyInfo2.SerialNumber}'");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SKI, keyInfo2.SKI))
                diffs.Add($" KeyInfo.SKI: {keyInfo1.SKI}, {keyInfo2.SKI}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SubjectName, keyInfo2.SubjectName))
                diffs.Add($" KeyInfo.SubjectName: {keyInfo1.SubjectName}, {keyInfo2.SubjectName}");
        }

        public static void GetDiffs(Reference reference1, Reference reference2, List<string> diffs)
        {
            if (reference1 == null && reference2 == null)
                return;

            if (reference1 == null && reference2 != null)
                diffs.Add($" reference1 == null && reference2 != null");

            if (reference1 != null && reference2 == null)
                diffs.Add($" reference1 != null && reference2 == null");

            if (!IdentityComparer.AreStringsEqual(reference1.DigestAlgorithm, reference2.DigestAlgorithm))
                diffs.Add($" Reference.DigestAlgorithm: {reference1.DigestAlgorithm}, {reference2.DigestAlgorithm}");

            if (!IdentityComparer.AreStringsEqual(reference1.Uri, reference2.Uri))
                diffs.Add($" Reference.Uri: {reference1.Uri}, {reference2.Uri}");

            if (reference1.TransformChain.TransformCount != reference2.TransformChain.TransformCount)
                    diffs.Add($" Reference.TransformChain.TransformCount: {reference1.TransformChain.TransformCount}, {reference2.TransformChain.TransformCount}");
            else if (reference1.TransformChain.TransformCount > 0)
            {
                for (int i = 0; i < reference1.TransformChain.TransformCount; i++)
                {
                    if (reference1.TransformChain[i].GetType() != reference2.TransformChain[i].GetType())
                        diffs.Add($" Reference.TransformChain[{i}].GetType(): {reference1.TransformChain[i].GetType()} : {reference2.TransformChain[i].GetType()}");
                }
            }
        }

        public static void GetDiffs(Signature signature1, Signature signature2, List<string> diffs)
        {
            if (signature1 == null && signature2 == null)
                return;

            if (signature1 == null && signature2 != null)
                diffs.Add($" signature1 == null && signature2 != null");

            if (signature1 != null && signature2 == null)
                diffs.Add($" signature1 != null && signature2 == null");

            if (!IdentityComparer.AreStringsEqual(signature1.Id, signature2.Id))
                diffs.Add($" signature.Id: {signature1.Id}, {signature2.Id}");

            GetDiffs(signature1.KeyInfo, signature2.KeyInfo, diffs);
            GetDiffs(signature1.SignedInfo, signature2.SignedInfo, diffs);
        }

        public static void GetDiffs(SignedInfo signedInfo1, SignedInfo signedInfo2, List<string> diffs)
        {
            if (signedInfo1 == null && signedInfo2 == null)
                return;

            if (signedInfo1 == null && signedInfo2 != null)
                diffs.Add($" signedInfo1 == null && signedInfo2 != null");

            if (signedInfo1 != null && signedInfo2 == null)
                diffs.Add($" signedInfo1 != null && signedInfo2 == null");

            if (!IdentityComparer.AreStringsEqual(signedInfo1.CanonicalizationMethod, signedInfo2.CanonicalizationMethod))
                diffs.Add($" SignedInfo.CanonicalizationMethod: {signedInfo1.CanonicalizationMethod}, {signedInfo2.CanonicalizationMethod}");

            if (!IdentityComparer.AreStringsEqual(signedInfo1.SignatureAlgorithm, signedInfo2.SignatureAlgorithm))
                diffs.Add($" SignedInfo.SignatureAlgorithm: {signedInfo1.SignatureAlgorithm}, {signedInfo2.SignatureAlgorithm}");

            GetDiffs(signedInfo1.Reference, signedInfo2.Reference, diffs);
        }
    }
}
