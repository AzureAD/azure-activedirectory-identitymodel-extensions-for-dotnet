//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
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
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    public interface ISignatureAlgorithm
    {
        // TODO - brentsch, add buffer offset???
        //void SignData(byte[] buffer, int offset, int count, object halg);
        byte[] SignData(byte[] buffer);

        // TODO - brentsch, do we need 'str' parameter? since we asked the key for a specific algorithm?
        //byte[] SignHash(byte[] rgbHash, string str);

        //bool VerifyData(byte[] buffer, object halg, byte[] signature);

        // TODO - brentsch, do we need 'str' parameter? since we asked the key for a specific algorithm?
        //bool VerifyHash(byte[] rgbHash, string str, byte[] rgbSignature);
        bool VerifyData(byte[] data, byte[] rgbSignature);
    }
}
