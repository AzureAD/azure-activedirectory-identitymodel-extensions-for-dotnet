using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Interface that defines methods to serialize and deserialize configuration metadata.
    /// </summary>
    public interface IConfigurationSerializer<T> where T : class
    {
        /// <summary>
        /// Serializes the metadata object into a string.
        /// </summary>
        /// <param name="metadata">Metadata object for serialization.</param>
        /// <returns>The string representation of the configuration metadata to be deserialized.</returns>
        string Serialize(T metadata);

        /// <summary>
        /// Deserialize a string to configuration metadata object.
        /// </summary>
        /// <param name="serializedString">The string representation of the configuration metadata to be deserialized.</param>
        /// <returns>Configuration metadata object.</returns>
        T Deserialize(string serializedString);
    }
}
