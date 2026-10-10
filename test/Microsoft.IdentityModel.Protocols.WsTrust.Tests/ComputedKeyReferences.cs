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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

using System;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public static class PSHA1
    {
        public static ComputedKeyMaterial Reference128_1 => new ComputedKeyMaterial("zyWv2YzpTqni7xMbZe4EE5EAdtNYZAcrAe5DU5qcZ5M=", "iyO21lrrmRDm9cUMC6RZRqAJ16JuRrRLOM7fGR3QHFw=", "ixTqFuS9mii2fkv1/z3BbQ==", 128);

        public static ComputedKeyMaterial Reference128_2 => new ComputedKeyMaterial("YRqi0pVqeM9Lmty6rc89hDrd5Mai3eeZ42tkvnfTtwY=", "t6ZqbelHtkv9CxfOjQWaF6jT3cdGwd4RhLcPNphlnf0=", "YuIMdylA6JauSzmmirjA0g==", 128);

        public static ComputedKeyMaterial Reference128_3 => new ComputedKeyMaterial("MjkyMIzScd3OHCuMTkwwnw==", "cCMpueP2bEu96Vc3bRfXuw==", "An3ijk/tlNUhDMhxwlvlSw==", 128);

        public static ComputedKeyMaterial Reference128_4 => new ComputedKeyMaterial("5brubdduHWNywXWPcRq8rw==", "fuExSIlmtCUzcJMW76kQzQ==", "HAzeHgRspMxMDE7MEDBATA==", 128);

        public static ComputedKeyMaterial Reference256_1 => new ComputedKeyMaterial("Tq8ysLdDYf4SRAzKlKWaf14shAbEANn57emcsU+Uzfw=", "OdlDaIG2ND9CtF8EseCHpRZ6iiIDVxiV2+Z7O7mXDIs=", "LdNuhTLMQzJQxjfQpULDuJQxvcDnyw+/Ez8DyS8QI8g=", 256);

        public static ComputedKeyMaterial Reference256_2 => new ComputedKeyMaterial("/tWCs/QgG3BFLjL6eJ9+oyUXA4i5A0p+ZmGGIdWZymc=", "V8SpcxeTAeY94TILrUpoMoCE8gR1WafwcOL/PDLRLuA=", "6cyhRfSSaiyYZWW4hmV17xI3Hm5pBIDgHyv05EH8bKY=", 256);

        public static ComputedKeyMaterial Reference256_3 => new ComputedKeyMaterial("L5eQURwNfImKc6mPcXyXSHj7nsdzyrWxJ+DPqqh6VT43WHkBRfBDqrG7YAWeENp+g96k9anfDTVEq+OOvSJyLjvLwbnJAlnM1/1+MFxzHpMgUiuWilRxgO4Nbxs+oILShxOUsm/6gryFqrbUv39NxSsQ3Q5i/RP7J9gxy+BBc6rL2ODLVvo1EdtetE89u7Wx2B9XoWXtXgO3PiZtnzszR3TEyL3jjPUAG3b8phnCYbs7Mkv7Kqu3b7xfddhLHmPHaQ9MVqY4AwV30mVdZ9ASZvOIevTDIOotaUtyEUl+hv8WhISmVZMED64dQG4gs8vXypseX6SI7eBC3xBlc4uFJAI4OKe2AddKOI+PhnuzI5KumRP+pJd1iYObfsLjs4kjp21PAE7B8GBob4arLIw3SawC9a56BRr8DKNBSOzwD0VfHHHzBkpgq9DeCM0cM8Wq2j27QhmUlJ2gG7b7xTee609/6kHswEVjPEb3jf9o54tFd3Zqe3O/gCQKeV5pw9cCYEA/ojMyzgtlEfkVyR01tWwmjCNaL+hrMcYZ9V/m7aiYjSZj2hNQzdR2YBLXHTHituxTDMuxgEWB+O5KoTvd1zLpe0YA6/fRAKBHEZuMhJ31GHoYsAjvjyKUnrWiCsNQFHwWo7mYNlP04shnJtV0XaYU5bbfZxxK2Zt/4SBN5S4=", "2pVPN39AZN08H4n6/fTLZbUZuYpNsE4c2lobVMrS5YjF8cKIHxHJpk/me+am1X+AAHNXmxSYBcG4VUzcXmGU5MGECxvi8JUK06YtzvDIAx11hSkJUiMCf2SI3TQ59TlnbAVqufyzXdRK0P5a2CtSMZzHo4BuLPgVxG92gPOL0j2DyWcQxsoBew6dsCQIiqEJzLbHQ5bYT2E1JKZxPJnaMgjh5zzzzWCrb2hAuV+X5SykFCnj0J1ycB9bQHyBhrOITyfocUDORxMbLTU67+3pBpOHlbtvV7KRGzs8ilO/Wi8n4PtjnWqMK3AO+FpzSy3FsLwuJUaPeiBhWCcKTnfTvGItbEblI1XC4yg9EsMox7WqI13NR2KHIxC5xoRIQMLsDsK/FmXEQit4ClCoker95vXPu1mwVvC1lEdAmHgrd4Rquuuy1rlejVhJgaSFg9FUYzO7CUxWRHeT/8J5Z8Pl+bwbhJzcxGB7GbvtU2PQ5NgcAipxSd2xCZp3Q8pRuuopTuZUk+wiaO0Ko06nyjYJYiqDcACm0fv0hMNBjEqdp0CWr4QPBgkgdpQOEgubibXjkCofW+QwNmwsU8kpIjrChnQ9gq2mKey1B7Qy1ntdggJl/OwrfKdjWKyrcMhV0nEB0AywUrV5PMdCR4tPqQoJL6TOm+rnHcXVM15+QC2oqbE=", "r8QOwaINXtVGc90JjLFjtSyQZlrzEUlPLs//OSzbxJc=", 256);

        public static ComputedKeyMaterial Reference256_4 => new ComputedKeyMaterial("Ir36tJDsA3S1abtfUp7oelnZV0ef3xBki2Msb9XVAzfFjlT7iBtxhPyI+tfnKAQkh9/3fGoP71kRDoXtC/v+Jcn3FOZg62HGdWyApCm/9nkoxk4nxLThRfCspHin8oFxIuUGvH/MRpcO7twRUV6EuSbZJKoWBMaaGJd9S7z3u0xGEBN8KS3VpQWeUSszTj2Lokrcp9ssvKve/hPyu5NNPO1wdod3FBLoQy0KyN6pNK3HfmX2hOenAUUgPpzvT+tyqyXgl6n3cBtcYDd26dU0X7/uDnbav2fTiJAofiXZS928zV2QRXHCfqs7gefQ9cbRzVJb+/yq4iRShMLTKSmPckWdQXpIIkMgIuS0plVLnL1Y3gZTe2gjmLIPSxf0gqIusFQ+kuhpIbiEvBJqxbn/nY9v+QFXrLBd1AAdMEx5/wsm6wAe8UbpkDI3SsvxedY7EzZvT8yj3jMlziyhPzFWLRaXgqNO4Usles79fHai2nmHe3dFtkIQDE1BgCLjO6IDTbVfDsbS52wrgO61kQlkVT2OFxJAWzmgB3N1CTdxc784UPj8Tdww26xU3LMd/QZkFC6g+aM4cxa7w5gtqHtnkpeZ84jOj4q2Uo3/pd3hYLJJhWoe1gI/9mzXUiT8kUegc0kK1pWxsyMUqWdHWiboQOnNNTBffd3En1WSUVzJfj8=", "flrDPAT0sPc7W9uaaG2RdKjA/1UMMR9u+PK3OX+FCGzBdJMRKQUutWO2dN6RUR5JnYMJ4ijYWjv9D/mSVVOFG0XSGaRHseIg30LOhrw9fQUD+40qRdctUSVA07O4oOr/Qvvc9kvlT6cnUmpmxVczFWdJ5hCnpBXb4P/Kf7EDgmyD/W/aGp4QNfMVqkSzXSzLXrErAiFs1gqGC370aAMaI2wOMsy4S4ipGoaaLZBeyOAJy/obIPBZXyG1jYFgZ82YgjX4zwcUnn1wIlarxg5M9ef+xxc2xAN43ea42TJjZ0LoEGP/ijOidAl8CvUTn7+H/hJ5SDbCYesFFkJEyf6zY5D8WDByP2RmFvuwXDKg+aLa6UlkTSR9wkNQPORdD4oME7O+M496iP3HtM/4pLurqQajSiS8tvt0tdPagbVRVk4i55cyJ6ZCaLmNzy/lsyhnGyO0+6biV9qzIeJgVhtADznZ2E7XrZbZ7+ihuEHNKMCIItHpWVhGXOrrch0NSB8J9NZ4dD3ckYkB6y+Mq8Wx2i1ZGG5j0i+eGEGDsbaTPHVMYmrn+FhS7q3JG/CgshpjjpFhzu+fbpFUVe4pJBLmnYiIcVKq2qHi3ldz2Je9ZswgG4+rtPm2dJFW8vUKeRKvhfxz8nBRBRSk9LipwbRcVN/K39DPssIuSL1zQ2YUR/g=", "DcXFLCsTADlJ3CR84NfZ20S7D4WGN18Kvz2Ds27F26g=", 256);

        public static ComputedKeyMaterial Reference512_1 => new ComputedKeyMaterial("p5c9QO3Y3AXPRHC5SUN7Fd9qowhINnledi522JxR4/3bh+aJnvBjCaSpXhqBP0ofR9invZkbi0Gl1xx/Bo++5fRuyghVkhhvkQcpBkOuhfGwKysInHPLOq8RxWqRxXv+jaXv/f6W9DWpGGL/V9LPehAZC/WLQ2yuYs/RaP2aTmHc9JMeOOa9hzIJFw+FLbx9tW3NEs90VP3iIfBUA8m1qsEgk5DdP1PsHQ35V0f2SRr26MHFFLWtHPUIG18hRlUjL1T3w9/MNkMog2HnQ/YlMBuU+yBEdagycEWFqmW7frWB919CaQX/t7/uIRSlhTHlf2S9np6MI0rY4/IfcrPZwo1YFaANM44AkNtqdgQW+rpNDg+Vm0ZL6kEMrUusbhj7YNe+mYYq8N6od+xpYCYU2jYRg9OdsESCE7i5lbtufMWWVtUa/pduE70ahX2I4BmV5rbNR3rk84vWlZn97Ef4n/QgvnXusgGoOgTnjPw/w4aJU5sFH++1uMRwOK8iIpG1jzwefgdC9aKbbv61/39ekXTE46GpBmmMi6uBDkgJJeSymoNces1qJYbfhkrTLBE2P3TVRKT55cgCt1Qjgng5M/yjpqw4mi7uxNKEzCW15UqU6l1CYNOQONAjeXDE7AcFGNvqcbGNOcfnO/sXj92cHa3CtbZ/oiQHO0Hwl8r82eM=", "xV/V1gVrZCbCyzwK85ZATlSaVuUUwshMd2F0DVou2VIoDZ23d09DQ8QrE2e/J18XX9zCMT80pvRMHcNcDgV+T0Gk/jMUY251CqVmTPTcrhEuZehaZQWQvtog6EwXCPX+55WBXbM0vcK8pFfLCnSCor9RFvks5Ft6OZeA0lLLey3akW/5YjV3XGfM7D4PY08vGPCWHRYPmo70xRuvybxXpNSHj/gDO5NYjAO1O4NjPAb91FKodX5XxPxFhOLcx/kAGqrPiSuDGwYiJtO6rvc7cGUVOKODu/B2bqcp4rb1Dvjs08PGUNlMqvh+gIEz3hj4oCgIAAx3kyb4LWHPrWq99aie4lwXHXAm/ZTMmdKvysbwbL8by7FkFBaervgklPdhPJTEnbj1Av4lD87H8yaiTqHFJ/K9wnxrocKlFAM4HvgNmhCpBEgRmljT2T/XndxruKGycFLjT/OmpTPy+ox7vITkUm968uTnum6FG1YTaAEUtTSpVUv9znAJi7gKf2n619/srwAtg2P2adjSFV6esFUApm6RA3dXNCF8xoM594ktqyHrq1aS8+jL5txVhc+Nz99hzhZRwrB2o8Soksqd0r9gqUB1YBfL874N3NuY1QYO1QEOZcXogbH+75XjTladEdrHYNe8+R6uA+dlCfVFUUOqcQ836YzeBmGNaoP+c7I=", "rjUJlvIT6lOiMvgzoYjwkCFwcbHZahRPmoW6iGu03wONQaRm/yiY9UuinMze/SfOMSz7U3NRfQvoNKbxjvemew==", 512);

        public static ComputedKeyMaterial Reference512_2 => new ComputedKeyMaterial("mgwzIqHxbFKFQaYNKM52stsemaIozFkpSKhZfLcVbcsybJQz6VBGsH/fAHRgOCGXxvlPVbnFS6VG9FZNgKyKaI4Yur7WSJ094lwXTnbEeIkACjP9g6hS7SR+YFCeILMSr8dQJ3/AqTnoQ7AKlsXHqvDMuhrpKMnS9uuUMspmZvEY3KWMkpMTf6zxqspQXBsuUVu/oiY83k7B3Yvb6PixaLTlIUrE4UYZ/H7ySdmgmEeIkIH8gjZMWxgAM+8CEEJm8ecHt2DnsqOzxKHwqnIpgHmZ6itzPeTg/abMvHJ1TwrwqZZnQ757lJrq+LyUKsnJkNNJzoOQfJeEd91zvtKtQ91VwG3jhEracpSHW9x1qNyRHcOrbyfj4/EiyrJzcWdQTr1WnR39j+fNqlr8rkqkDS5t/zfoAqM4NT8ijjLJyIJog1Zmr4c1CA6a2s759Iy3tPbp/1WmqBQAGLewgjYy5s6Cai6zcSMew0XkQ9qLaNEMTlsUHcp1cksy/Z/jD3pOAriJU8QvZrWjDRZ9wcxymmg2013ROQdF+nItSzcfKFlM8okIgsEFm+Ako+zusrCYeMiPjiiysp7hXHEDgm8FVgMHpwBoMCIb/AwlNYz7vXGh0wNjcCy8wD3FKjC+EL6GKwItpp1u15EZcQJMByqajDJY08kRh8OaYWSBvvuVwMc=", "XExU9GCAPMpsr79by8tV8yJrejDNKWCgQcKqNdv+QueF5j4L8c9Z5iM5aza9HMXW8jV/WLIesr90C1CE94+UobNHXXJY021brD7dJkYMjPK/L0wFQD+/eQbiVPCGXi4alXjblN8mlsYJ9VLkDZ9Y6jzbTvtf5DX3zW/PpN9SqYTEEWjuQPRk4Et40Rdd7dxZLvFkPL2hry/li0sPqtq9lwTp+Iuxdin91UZCtpiG5f03cpcXLY/YI0MKV9Brkga49S5DczHwEXcapGCoIh3Rzav6clJMIRQzI+WJXhP9VMcOlK1zya2DYjIig7i7mSPx+/4FlWHZgiX6El0cmXMOqLjovjo6KoBJWFvpVIZIEhOleXO74fhEhgljHwWWAtNoKEed5xxFpy7CXkM7rpHofsgrYmy7aaZ/9tgebbvbnidPLPEvgsfiRE8OS6MG/J8bSlbbiusuYh72aRVX9h2WbT6FA+V9a8V7WF48ZvZD6DmsDs5FNx+B6RyA8cxMf50ItM6eXhoqaGKDc5Rr4r0u0R9gOb32mC3/4Eek5Z706NNjxxNffa5JfKsYzrtJzGNdqcJ6GM9MxCseaAY+wuJKpnALa6XQ36Jx+wWD/6mbK3Vwmeo84RJHom8xDcDXJ9jVJ0vhoxh1+5Tc/ise885tdOrAO2SWDrWI+ShvodO2L+s=", "FDOfSoMTVe9JmkNVtYyN0/Hgl7B350Ey7nNM9Zz5X3qLHalMH2Yu+BqDDwO4CcchHQc5d9FiuTeVwNnbQh3CyQ==", 512);
    }

    public class ComputedKeyMaterial
    {
        public ComputedKeyMaterial(string issuerEntropy, string requestorEntropy, string derivedKey, int keySizeInBits)
        {
            DerivedKeyString = derivedKey;
            DerivedKeyBytes =  string.IsNullOrEmpty(derivedKey) ? null : Convert.FromBase64String(derivedKey);
            IssuerEntropyString = issuerEntropy;
            IssuerEntropyBytes = string.IsNullOrEmpty(issuerEntropy) ? null : Convert.FromBase64String(issuerEntropy);
            KeySizeInBits = keySizeInBits;
            RequestorEntropyString = requestorEntropy;
            RequestorEntropyBytes = string.IsNullOrEmpty(requestorEntropy) ? null : Convert.FromBase64String(requestorEntropy);
        }

        public static string EntropyTooSmall => Convert.ToBase64String(new byte[2]);

        public static string EntropyTooLarge => Convert.ToBase64String(new byte[8192 * 4]);

        public static string Entropy128 => "GS5olVevYMI4vW1Df/7FUpHcJJopTszp6sodlK4/rP8=";

        public static string DerivedKey128 => "ZMOP1NFa5VKTQ8I2awGXDjzKP+686eujiangAgf5N+Q=";

        public byte[] DerivedKeyBytes { get; }

        public string DerivedKeyString { get; }

        public byte[] IssuerEntropyBytes { get; }

        public string IssuerEntropyString { get; }

        public int KeySizeInBits { get; }

        public byte[] RequestorEntropyBytes { get; }

        public string RequestorEntropyString { get; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
