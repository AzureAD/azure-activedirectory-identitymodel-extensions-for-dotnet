//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    // for sequential use by one thread
    public class SignatureResourcePool
    {
        const int BufferSize = 64;
        CanonicalizationDriver canonicalizationDriver;
        HashStream hashStream;
        HashAlgorithm hashAlgorithm;
        XmlDictionaryWriter utf8Writer;
        byte[] encodingBuffer;
        char[] base64Buffer;

        public char[] TakeBase64Buffer()
        {
            if (this.base64Buffer == null)
            {
                this.base64Buffer = new char[BufferSize];
            }
            return this.base64Buffer;
        }

        public CanonicalizationDriver TakeCanonicalizationDriver()
        {
            if (this.canonicalizationDriver == null)
            {
                this.canonicalizationDriver = new CanonicalizationDriver();
            }
            else
            {
                this.canonicalizationDriver.Reset();
            }
            return this.canonicalizationDriver;
        }

        public byte[] TakeEncodingBuffer()
        {
            if (this.encodingBuffer == null)
            {
                this.encodingBuffer = new byte[BufferSize];
            }
            return this.encodingBuffer;
        }

        public HashAlgorithm TakeHashAlgorithm(string algorithm)
        {
            if ( this.hashAlgorithm == null )
            {
                if ( string.IsNullOrEmpty( algorithm ) )
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException("algorithm, EmptyOrNullArgumentString"));
                }

                // TODO - hash algorithms are serverd up by keys and factories
                this.hashAlgorithm = null;// CryptoHelper.CreateHashAlgorithm( algorithm );
            }
            else
            {
                this.hashAlgorithm.Initialize();
            }
           
            return this.hashAlgorithm;
        }

        public HashStream TakeHashStream(HashAlgorithm hash)
        {
            if (this.hashStream == null)
            {
                this.hashStream = new HashStream(hash);
            }
            else
            {
                this.hashStream.Reset(hash);
            }
            return this.hashStream;
        }

        public HashStream TakeHashStream(string algorithm)
        {
            return TakeHashStream(TakeHashAlgorithm(algorithm));
        }

        public XmlDictionaryWriter TakeUtf8Writer()
        {
            if (this.utf8Writer == null)
            {
                this.utf8Writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false);
            }
            else
            {
                ((IXmlTextWriterInitializer) this.utf8Writer).SetOutput(Stream.Null, Encoding.UTF8, false);
            }
            return this.utf8Writer;
        }
    }
}
