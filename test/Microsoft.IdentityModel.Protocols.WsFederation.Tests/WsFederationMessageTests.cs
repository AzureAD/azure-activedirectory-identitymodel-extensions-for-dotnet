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
using System.Collections.Generic;
using System.Collections.Specialized;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

    /// <summary>
    /// 
    /// </summary>
    public class WsFederationMessageTests
    {
        [Fact]
        public void GetSets()
        {
            var type = typeof(WsFederationMessage);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 27, $"Number of properties has changed from 27 to: {properties.Length}, adjust tests");

            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("Wa", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wattr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wattrptr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wct", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wctx", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wencoding", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wfed", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wfresh", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Whr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wp", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wpseudo", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wpseudoptr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wreply", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wreq", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wreqptr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wres", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wresult", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wresultptr", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Wtrealm", new List<object>{(string)null, Guid.NewGuid().ToString()}),

                },
                Object = new WsFederationMessage(),
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", context.Errors);
        }

        [Theory, MemberData("MessageTheoryData")]
        public void ConstructorTest(WsFederationMessageTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ConstructorTest", theoryData);
            try
            {
                // check default constructor
                var wsFederationMessage1 = new WsFederationMessage
                {
                    IssuerAddress = theoryData.IssuerAddress,
                    Wreply = theoryData.Wreply,
                    Wct = theoryData.Wct
                };

                Assert.Equal(theoryData.IssuerAddress, wsFederationMessage1.IssuerAddress);
                Assert.Equal(theoryData.Wreply, wsFederationMessage1.Wreply);
                Assert.Equal(theoryData.Wct, wsFederationMessage1.Wct);

                // check copy constructor
                WsFederationMessage wsFederationMessage2 = new WsFederationMessage(wsFederationMessage1);

                Assert.Equal(theoryData.IssuerAddress, wsFederationMessage2.IssuerAddress);
                Assert.Equal(theoryData.Wreply, wsFederationMessage2.Wreply);
                Assert.Equal(theoryData.Wct, wsFederationMessage2.Wct);

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        [Theory, MemberData("GetTokenTheoryData")]

        public void GetTokenTest(WsFederationMessageTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.GetTokenTest", theoryData);
            try
            {
                var token = theoryData.WsFederationMessageTestSet.WsFederationMessage.GetToken();
                Assert.Equal(theoryData.Token, token);
                if (theoryData.TokenValidationParameters != null)
                {
                    var tokenHandler = new Saml2SecurityTokenHandler();
                    tokenHandler.ValidateToken(token, theoryData.TokenValidationParameters, out SecurityToken validatedToken);
                }
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<WsFederationMessageTheoryData> GetTokenTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMessageTheoryData>
                {
                    new WsFederationMessageTheoryData
                    {
                        First = true,
                        TokenValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = true,
                            ValidIssuer = "https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/",
                            ValidateAudience = true,
                            ValidAudience = "spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4",
                            ValidateLifetime = false,
                        },
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Saml2_Valid
                            }
                        },
                        Token = ReferenceXml.Token_Saml2_Valid,
                        TestId = "WsFederationMessage getToken test"
                    },
                    new WsFederationMessageTheoryData
                    {
                        TokenValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = true,
                            ValidIssuer = "https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/",
                            ValidateAudience = true,
                            ValidAudience = "spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4",
                            ValidateLifetime = false,
                        },
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Saml2_Valid_With_Spaces
                            }
                        },
                        Token = ReferenceXml.Token_Saml2_Valid,
                        TestId = "WsFederationMessage getToken test with white spaces"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Dummy_WsTrust1_3
                            }
                        },
                        Token = ReferenceXml.Token_Dummy,
                        TestId = "WsFederationMessage getToken test with WsTrust 1.3"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Dummy_WsTrust1_4
                            }
                        },
                        Token = ReferenceXml.Token_Dummy,
                        TestId = "WsFederationMessage getToken test with WsTrust 1.4"
                    }
                };
            }
        }

        [Theory, MemberData("GetTokenNegativeTestTheoryData")]

        public void GetTokenNegativeTest(WsFederationMessageTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.GetTokenNegativeTest", theoryData);
            try
            {
                var token = theoryData.WsFederationMessageTestSet.WsFederationMessage.GetToken();
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<WsFederationMessageTheoryData> GetTokenNegativeTestTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMessageTheoryData>
                {
                    new WsFederationMessageTheoryData
                    {
                        First = true,
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Saml2_Missing_RequestedSecurityTokenResponse
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(WsFederationException), "IDX22902:"),
                        TestId = "WsFederationMessage getToken negative test: missing RequesteSecurityTokenResponse element"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Saml2_Missing_RequestedSecurityToken
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(WsFederationException), "IDX22902:"),
                        TestId = "WsFederationMessage getToken negative test: missing RequesteSecurityToken element"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Dummy_Invalid_Namespace
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(WsFederationException), "IDX22902:"),
                        TestId = "WsFederationMessage getToken negative test: unsupported namespace"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Dummy_WsTrust1_3_multiple_tokens
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(WsFederationException), "IDX22903:"),
                        TestId = "WsFederationMessage getToken negative test: wstrust 1.3, more than one token"
                    },
                    new WsFederationMessageTheoryData
                    {
                        WsFederationMessageTestSet = new WsFederationMessageTestSet
                        {
                            WsFederationMessage = new WsFederationMessage
                            {
                                Wresult = ReferenceXml.WResult_Dummy_WsTrust1_4_multiple_tokens
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(WsFederationException), "IDX22903:"),
                        TestId = "WsFederationMessage getToken negative test: wstrust 1.4, more than one token"
                    }
                };
            }
        }

        [Theory, MemberData("MessageTheoryData")]

        public void ParametersTest(WsFederationMessageTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ParametersTest", theoryData);
            try
            {
                var wsFederationMessage = new WsFederationMessage
                {
                    IssuerAddress = theoryData.IssuerAddress,
                    Wreply = theoryData.Wreply,
                    Wct = theoryData.Wct
                };

                Assert.Equal(theoryData.IssuerAddress, wsFederationMessage.IssuerAddress);
                Assert.Equal(theoryData.Wreply, wsFederationMessage.Wreply);
                Assert.Equal(theoryData.Wct, wsFederationMessage.Wct);

                // add parameter
                wsFederationMessage.SetParameter(theoryData.Parameter1.Key, theoryData.Parameter1.Value);

                // add parameters
                var nameValueCollection = new NameValueCollection
                {
                    { theoryData.Parameter2.Key, theoryData.Parameter2.Value },
                    { theoryData.Parameter3.Key, theoryData.Parameter3.Value }
                };
                wsFederationMessage.SetParameters(nameValueCollection);

                // validate the parameters are added
                Assert.Equal(theoryData.Parameter1.Value, wsFederationMessage.Parameters[theoryData.Parameter1.Key]);
                Assert.Equal(theoryData.Parameter2.Value, wsFederationMessage.Parameters[theoryData.Parameter2.Key]);
                Assert.Equal(theoryData.Parameter3.Value, wsFederationMessage.Parameters[theoryData.Parameter3.Key]);

                // remove parameter
                wsFederationMessage.SetParameter(theoryData.Parameter1.Key, null);

                // validate the parameter is removed
                Assert.Equal(false, wsFederationMessage.Parameters.ContainsKey(theoryData.Parameter1.Key));

                // create redirectUri
                var uriString = wsFederationMessage.BuildRedirectUrl();
                Uri uri = new Uri(uriString);

                // convert query back to WsFederationMessage
                var wsFederationMessageReturned = WsFederationMessage.FromQueryString(uri.Query);

                // validate the parameters in the returned wsFederationMessage
                Assert.Equal(theoryData.Parameter2.Value, wsFederationMessageReturned.Parameters[theoryData.Parameter2.Key]);
                Assert.Equal(theoryData.Parameter3.Value, wsFederationMessageReturned.Parameters[theoryData.Parameter3.Key]);

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<WsFederationMessageTheoryData> MessageTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMessageTheoryData>
                {
                    new WsFederationMessageTheoryData
                    {
                        First = true,
                        IssuerAddress = @"http://www.gotjwt.com",
                        Parameter1 = new KeyValuePair<string, string>("bob", "123"),
                        Parameter2 = new KeyValuePair<string, string>("tom", "456"),
                        Parameter3 = new KeyValuePair<string, string>("jerry", "789"),
                        Wct = Guid.NewGuid().ToString(),
                        Wreply = @"http://www.relyingparty.com",
                        TestId = "WsFederationMessage test"
                    }
                };
            }
        }

        [Theory, MemberData("QueryStringTheoryData")]

        public void QueryStringTest(WsFederationMessageTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.QueryStringTest", theoryData);
            var context = new CompareContext($"{this}.QueryStringTest, {theoryData.TestId}");
            try
            {
                var wsFederationMessage = WsFederationMessage.FromQueryString(theoryData.WsFederationMessageTestSet.Xml);
                theoryData.ExpectedException.ProcessNoException();
                IdentityComparer.AreWsFederationMessagesEqual(wsFederationMessage, theoryData.WsFederationMessageTestSet.WsFederationMessage, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsFederationMessageTheoryData> QueryStringTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMessageTheoryData>
                {
                    new WsFederationMessageTheoryData
                    {
                        First = true,
                        WsFederationMessageTestSet = ReferenceXml.WsSignInTestSet,
                        TestId = nameof(ReferenceXml.WsSignInTestSet)
                    }
                };
            }
        }

        public class WsFederationMessageTheoryData : TheoryDataBase
        {
            public WsFederationMessageTestSet WsFederationMessageTestSet { get; set; }

            public string IssuerAddress { get; set; }

            public KeyValuePair<string, string> Parameter1 { get; set; }

            public KeyValuePair<string, string> Parameter2 { get; set; }

            public KeyValuePair<string, string> Parameter3 { get; set; }

            public string Token { get; set; }

            public TokenValidationParameters TokenValidationParameters { get; set; }

            public string Wa { get; set; }

            public string Wauth { get; set; }

            public string Wct { get; set; }

            public string Wctx { get; set; }

            public string Wencoding { get; set; }

            public string Wfed { get; set; }

            public string Wfresh { get; set; }

            public string Whr { get; set; }

            public string Wp { get; set; }

            public string Wpseudo { get; set; }

            public string Wpseudoptr { get; set; }

            public string Wreply { get; set; }

            public string Wreq { get; set; }

            public string Wreqptr { get; set; }

            public string Wres { get; set; }

            public string Wresult { get; set; }

            public string Wresultptr { get; set; }

            public string Wtrealm { get; set; }
        }
    }
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
}
