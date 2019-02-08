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
using System;

namespace Microsoft.IdentityModel.JsonExtensions
{
    /// <summary>
    /// 
    /// </summary>
    public class NewtonsoftJsonAdapter : IJsonConvertible
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="input"></param>
        /// <returns></returns>
        public T Convert<T>(object input)
        {
            T value;

            if (input is Microsoft.IdentityModel.Json.Linq.JToken jToken)
            {
                var newtonsoftObject = Newtonsoft.Json.Linq.JToken.Parse(jToken.ToString(Microsoft.IdentityModel.Json.Formatting.None));
                value = newtonsoftObject.ToObject<T>();
            }
            else
            {
                value = (T)input;
            }

            return value;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public bool TryConvert<T>(object input, out T output)
        {
            try
            {
                if (input is Microsoft.IdentityModel.Json.Linq.JToken jToken)
                {
                    var newtonsoftObject = Newtonsoft.Json.Linq.JToken.Parse(jToken.ToString(Microsoft.IdentityModel.Json.Formatting.None));
                    output = newtonsoftObject.ToObject<T>();
                }
                else
                {
                    output = (T)input;
                }

                return true;
            }
            catch (Exception)
            {
                output = default(T);
                return false;
            }
        }
    }
}
