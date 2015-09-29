using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class JsonExtensionsTests
    {
        [Fact(DisplayName = "JsonExtensionsTests: Test json with duplicate names")]
        public void TestJsonWithDuplicateNames()
        {
            try
            {

                string json = @"{""tag"":""value1"", ""tag"": ""value2""}";
                var jsonObject = JsonExtensions.DeserializeFromJson<object>(json);
            }
            catch(Exception ex)
            {
                Assert.Equal(ex.GetType(), typeof(ArgumentException));
                Assert.Contains("Property with the same name already exists on object.", ex.Message);
            }
        }

        [Fact(DisplayName = "JsonExtensionsTests: Test malformed json")]
        public void TestMalformedJson()
        {
            Assert.Throws<Newtonsoft.Json.JsonReaderException>(() => JsonExtensions.DeserializeFromJson<object>(@"{""tag"":""value""}ABCD"));
        }
    }
}
