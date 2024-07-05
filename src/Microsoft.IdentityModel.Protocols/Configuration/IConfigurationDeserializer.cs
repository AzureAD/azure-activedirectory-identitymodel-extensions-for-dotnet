using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public interface IConfigurationDeserializer<T> where T : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadata"></param>
        /// <returns></returns>
        T Deserialize(Span<byte> metadata);
    }
}
