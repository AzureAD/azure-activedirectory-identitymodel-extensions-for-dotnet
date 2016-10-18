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

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{    
    /// <summary>
    /// Test some key extensibility scenarios
    /// </summary>
    public class JwtSecurityTokenHandlerExtensibilityTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("DecryptTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void DecryptToken(TheoryParams theoryParams)
        {
            try
            {
                theoryParams.TokenHandler.DecryptTokenPublic(theoryParams.Token, theoryParams.TokenParts, theoryParams.ValidationParameters);
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<TheoryParams> DecryptTokenTheoryData()
        {
            var theoryData = new TheoryData<TheoryParams>();
            var tokenHandler = new PublicJwtSecurityTokenHandler();
            var tokenParts = new string[5] { "", "", "", "", "" };
            var header = new JwtHeader();
            header[JwtHeaderParameterNames.Enc] = JwtConstants.DirectKeyUseAlg;

            // Parameter validation
            theoryData.Add(new TheoryParams("Test1", null, null, null, tokenHandler, ExpectedException.ArgumentNullException()));
            theoryData.Add(new TheoryParams("Test2", "", null, null, tokenHandler, ExpectedException.ArgumentNullException()));
            theoryData.Add(new TheoryParams("Test3", "a.b.c.d.e", null, null, tokenHandler, ExpectedException.ArgumentNullException()));
            theoryData.Add(new TheoryParams("Test4", "a.b.c.d.e", new string[2], null, tokenHandler, ExpectedException.ArgumentNullException()));
            theoryData.Add(new TheoryParams("Test5", "a.b.c.d.e", new string[2], Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, ExpectedException.SecurityTokenException("IDX10606:")));
            theoryData.Add(new TheoryParams("Test6", "a.b.c.d.e", new string[3], Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, ExpectedException.SecurityTokenException("IDX10606:")));
            theoryData.Add(new TheoryParams("Test7", "a.b.c.d.e", new string[4], Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, ExpectedException.SecurityTokenException("IDX10606:")));
            theoryData.Add(new TheoryParams("Test8", "a.b.c.d.e", new string[6], Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, ExpectedException.SecurityTokenException("IDX10606:")));
            tokenParts = new string[5] { "", "", "", "", "" };
            theoryData.Add(new TheoryParams("Test9", "a.b.c.d.e", tokenParts, Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, new ExpectedException(typeof(SecurityTokenException), "IDX10613:") { Verbose = true }));
            tokenParts = new string[5] { "%%%", "", "", "", "" };
            theoryData.Add(new TheoryParams("Test10", "a.b.c.d.e", tokenParts, Default.AsymmetricEncryptSignTokenValidationParameters, tokenHandler, new ExpectedException(typeof(SecurityTokenException), "IDX10614:") { Verbose = true }));

            return theoryData;
        }

        public class TheoryParams
        {
            public TheoryParams(string testId, string token, string[] tokenParts, TokenValidationParameters validationParamters, PublicJwtSecurityTokenHandler tokenHandler, ExpectedException ee)
            {
                TestId = testId;
                Token = token;
                TokenParts = tokenParts;
                TokenHandler = tokenHandler;
                ValidationParameters = validationParamters;
                EE = ee;
            }

            public string TestId { get; set; }
            public string  Token { get; set; }
            public string[]  TokenParts { get; set; }
            public PublicJwtSecurityTokenHandler TokenHandler { get; set; }
            public TokenValidationParameters ValidationParameters { get; set; }
            public ExpectedException EE { get; set; }
        }
    }
}
