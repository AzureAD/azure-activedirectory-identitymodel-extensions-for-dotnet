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

using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;

using Claim = System.Security.Claims.Claim;
using ClaimsIdentity = System.Security.Claims.ClaimsIdentity;
using ClaimTypes = System.Security.Claims.ClaimTypes;
using ClaimValueTypes = System.Security.Claims.ClaimValueTypes;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Contains a nubmer of different claims sets used to test roundtripping claims sets.
    /// </summary>
    public static class ClaimSets
    {
        public static string ActorIssuer = "http://www.GotJwt.com/Actor";

        static Claim _actor             = new Claim( JwtRegisteredClaimNames.Actort, JwtTestTokens.Simple( ActorIssuer, ActorIssuer ).ToString() );
        static Claim _audience          = new Claim( JwtRegisteredClaimNames.Aud, "audClaimSets.Value" );
        static Claim _badHeaderType     = new Claim( JwtHeaderParameterNames.Typ, "BADDTYPE" );
        static Claim _expBadDateFormat  = new Claim( JwtRegisteredClaimNames.Exp, "BADDATEFORMAT" );
        static Claim _issuedAt          = new Claim( JwtRegisteredClaimNames.Iat, "issuedatClaimSets.Value" );
        static Claim _issuer            = new Claim( JwtRegisteredClaimNames.Iss,   "issuerClaimSets.Value" );
        static Claim _jwtId             = new Claim( JwtRegisteredClaimNames.Jti, "jwtIdClaimSets.Value" );
        static Claim _nbfBadDateFormat  = new Claim( JwtRegisteredClaimNames.Nbf, "BADDATEFORMAT" );
        static Claim _notAfter          = new Claim( JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate( DateTime.UtcNow + TimeSpan.FromHours( 1 ) ).ToString() );
        static Claim _notBefore         = new Claim( JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.UtcNow).ToString() );
        static Claim _principal         = new Claim( JwtRegisteredClaimNames.Prn, "princlipalClaimSets.Value" );
        static Claim _sub               = new Claim( JwtRegisteredClaimNames.Sub, "Subject.Value" );
        static Claim _type              = new Claim( JwtRegisteredClaimNames.Typ, "Type.Value" );
        
        public static IEnumerable<Claim> AllReserved
        {
            // these are all current reserved claims.
            // should be updated as the spec changes, refer to 
            // JwtConstants.cs
            get
            {
                yield return _actor;
                yield return _audience;
                yield return _issuedAt;
                yield return _issuer;
                yield return _jwtId;
                yield return _notAfter;
                yield return _notBefore;
                yield return _principal;
                yield return _sub;
                yield return _type;
            }
        }

        public static IEnumerable<Claim> Audience
        {
            get { yield return _audience; }        
        }

        public static IEnumerable<Claim> BadDateFormats
        {
            get 
            {
                yield return _nbfBadDateFormat;
                yield return _expBadDateFormat;
            }
        }

        public static IEnumerable<Claim> BadHeaderType
        {
            get { yield return _badHeaderType; }
        }

        public static IEnumerable<Claim> Empty
        {
            get { return new List<Claim>(); }
        }

        public static IEnumerable<Claim> Issuer
        {
            get { yield return _issuer; }
        }

        public static IEnumerable<Claim> Simple( string issuer, string originalIssuer )
        {
            return new List<Claim>()
            {
                new Claim( ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimsIdentity.DefaultNameClaimType, "Jean-Sébastien", ClaimValueTypes.String, issuer, originalIssuer ),
            };
        }

        public static IEnumerable<Claim> ActorClaimNotJwt( string issuer, string originalIssuer )
        {
            return new List<Claim>()
            {
                new Claim( ClaimTypes.Actor, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
            };
        }

        public static IEnumerable<Claim> AllInboundShortClaimTypes( string issuer, string originalIssuer, IEnumerable<Claim> extraClaims = null)
        {
            foreach ( KeyValuePair<string, string> pair in JwtSecurityTokenHandler.InboundClaimTypeMap )
            {
                yield return new Claim( pair.Key, pair.Value, ClaimValueTypes.String, issuer, originalIssuer );
            }

            if ( extraClaims != null )
            {
                foreach ( Claim c in extraClaims )
                {
                    yield return c;
                }
            }
        }

        public static IEnumerable<Claim> ExpectedInClaimsIdentityUsingAllInboundShortClaimTypes(string issuer, string originalIssuer, IEnumerable<Claim> extraClaims = null)
        {
            foreach (KeyValuePair<string, string> pair in JwtSecurityTokenHandler.InboundClaimTypeMap)
            {
                Claim claim = new Claim(pair.Value, pair.Value, ClaimValueTypes.String, issuer, originalIssuer);
                claim.Properties.Add(new KeyValuePair<string, string>(JwtSecurityTokenHandler.ShortClaimTypeProperty, pair.Key));
                yield return claim;
            }

            if (extraClaims != null)
            {
                foreach (Claim c in extraClaims)
                {
                    yield return c;
                }
            }
        }

        /// <summary>
        /// Returns an enumeration containing duplicate claims. Used to test dups.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="originalIssuer"></param>
        /// <returns></returns>
        public static IEnumerable<Claim> DuplicateTypes( string issuer, string originalIssuer )
        {
            return new List<Claim>
            {
                new Claim( ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Country, "USA_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Email, "user@contoso.com_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.GivenName, "Tony_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.HomePhone, "555.1212_2", ClaimValueTypes.String, issuer, originalIssuer ),
                new Claim( ClaimTypes.Role, "Sales_2", ClaimValueTypes.String, issuer, originalIssuer )
            };
        }

        /// <summary>
        /// Claims containing global unicode chars. Gleemed from a number of sources.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="originalIssuer"></param>
        /// <returns></returns>
        public static IEnumerable<Claim> GlobalClaims( string issuer, string originalIssuer )
        {
            yield return new Claim("Arabic", @"الراي", ClaimValueTypes.String, issuer, originalIssuer );
            yield return new Claim("Turkish1", @"ığIŞiĞİşçöÇÖ", ClaimValueTypes.String, issuer, originalIssuer );
            yield return new Claim("Turkish2", @"ĞİşÖ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("Chinese1", @"阿洛哈", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("Chinese2", @"洛矶", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("Japanese1", @"アロハ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("Japanese2", @"ロッキー<", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtA1", @"㐖㐗㐘㐙㐚㐛㐜㐝㐞㐟㐠㐡㐢㐣㐤㐥㐦㐧㐨㐩㐪㐫㐬㐭㐮㐯㐰㐱", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtA2", @"㱍㱎㱏㱐㱑㱒㱓㱔㱕㱖㱗㱘㱙㱚㱛㱜㱝㱞㱟㱠㱡㱢㱣㱤㱥㱦㱧㱨㱩㱪㱫㱬㱭㱮㱯㱰㱱㱲㱳㱴㱵㱶㱷", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtA3", @"䐧䐨䐩䐪䐫䐬䐭䐮䐯䐰䐱䐲䐳䐴䐵䐶䐷䐸䐹䐺䐻䐼䐽䐾䐿䑀䑁䑂", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtA4", @"䝰䝱䝲䝳䝴䝵䝶䝷䝸䝹䝺䝻䝼䝽䝾䝿䞀䞁䞂䞃䞄䞅䞆䞇䞈䞉䞊䞋䞌䞍䞎䞏䞐䞑䞒䞓䞔䞕䞖䞗䞘䞙䞚䞛䞜䞝䞞䞟䞠䞡䞢䞣䞤䞥䞦䞧䞨䞩䞪䞫䞬䞭䞮䞯䞰䞱䞲䞳䞴䞵䞶䞷䞸䞹䞺䞻䞼䞽䞾䞿䟀䟁䟂䟃䟄䟅䟆䟇䟈䟉䟊䟋䟌䟍䟎䟏䟐䟑䟒䟓䟔䟕䟖䟗䟘䟙䟚䟛䟜䟝䟞䟟䟠䟡䟢䟣䟤", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtA4", @"䱘䱙䱚䱛䱜䱝䱞䱟䱠䱡䱢䱣䱤䱥䱦䱧䱨䱩䱪䱫䱬䱭䱮䱯䱰䱱䱲䱳䱴䱵䱶䱷䱸䱹䱺䱻䱼䱽䱾䱿䲀䲁䲂䲃䲄䲅䲆䲇䲈䲉䲊䲋䲌䲍䲎䲏䲐䲑䲒䲓䲔䲕䲖䲗䲘䲙䲚䲛䲜䲝䲞䲟䲠䲡䲢䲣䲤䲥䲦䲧䲨䲩䲪䲫䲬䲭䲮䲯䲰䲱䲲䲳䲴䲵䲶䲷䲸䲹䲺䲻䲼䲽䲾䲿䳀䳁䳂䳃䳄䳅䳆䳇䳈䳉䳊䳋䳌䳍䳎䳏䳐䳑䳒䳓䳔䳕䳖䳗䳘䳙䳚䳛䳜䳝䳞䳟䳠䳡䳢䳣䳤䳥䳦䳧䳨䳩䳪䳫䳬䳭䳮䳯䳰䳱䳲䳳䳴䳵䳶䳷䳸䳹䳺䳻䳼䳽䳾䳿䴀䴁䴂䴃䴄䴅䴆䴇䴈䴉䴊䴋䴌䴍䴎䴏䴐䴑䴒䴓䴔䴕䴖䴗䴘䴙䴚䴛䴜䴝䴞䴟䴠䴡䴢䴣䴤䴥䴦䴧䴨䴩䴪䴫䴬䴭䴮䴯䴰䴱䴲䴳䴴䴵䴶䴷䴸䴹䴺䴻䴼䴽䴾䴿䵀䵁䵂䵃䵄䵅䵆䵇䵈䵉䵊䵋䵌䵍䵎䵏䵐䵑䵒䵓䵔䵕䵖䵗䵘䵙䵚䵛䵜䵝䵞䵟䵠䵡䵢䵣䵤䵥䵦䵧䵨䵩䵪䵫䵬䵭䵮䵯䵰䵱䵲䵳䵴䵵䵶䵷䵸䵹䵺䵻䵼䵽䵾䵿䶀䶁䶂䶃䶄䶅䶆䶇䶈䶉䶊䶋䶌䶍䶎䶏䶐䶑䶒䶓䶔䶕䶖䶗䶘䶙䶚䶛䶜䶝䶞䶟䶠䶡䶢䶣䶤䶥䶦䶧", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtB1", @"𠘣𠘤𠘥𠘦𠘧𠘨𠘩𠘪𠘫𠘬𠘭𠘮𠘯𠘰𠘱𠘲𠘳𠘴𠘵𠘶𠘷𠘸𠘹𠘺𠘻𠘼𠘽𠘾𠘿𠙀", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtB2", @"𥀿𥁀𥁁𥁂𥁃𥁄𥁅𥁆𥁇𥁈𥁉𥁊𥁋𥁌𥁍𥁎𥁏", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtB3", @"𡴥𡴦𡴧𡴨𡴩𡴪𡴫𡴬𡴭𡴮𡴯𡴰𡴱𡴲𡴳𡴴𡴵𡴶𡴷𡴸𡴹𡴺", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtB4", @"𧴒𧴓𧴔𧴕𧴖𧴗𧴘𧴙𧴚𧴛𧴜𧴝𧴞𧴟𧴠𧴡𧴢𧴣𧴤𧴥𧴦𧴧𧴨𧴩𧴪𧴫𧴬𧴭𧴮𧴯𧴰𧴱𧴲𧴳𧴴𧴵𧴶𧴷𧴸𧴹𧴺𧴻𧴼𧴽𧴾𧴿𧵀𧵁𧵂𧵃𧵄𧵅𧵆𧵇𧵈𧵉𧵊𧵋𧵌𧵍𧵎𧵏𧵐𧵑<", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("ExtB5", @"𪚶𪚷𪚸𪚹𪚺𪚻𪚼𪚽𪚾𪚿𪛀𪛁𪛂𪛃𪛄𪛅𪛆𪛇𪛈𪛉𪛊𪛋𪛌𪛍𪛎𪛏𪛐𪛑𪛒𪛓𪛔𪛕𪛖", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("EnteringIntlChars1", @"𠣁𩥺𨍝𦴿𥜢𤄅𢫨𡓋𪖄𨽧𧥉𦌬𤴏𣛲𢃕𠪸𩭰𨕓𦼶𥤙𤋼𢳟𡛁𠂤𩅝𧭀𦔣𤼆𣣩𢋋𠲮𩵧𨝊𧄭𥬐𤓲𢻕𡢸𠊛𩍔𧴷𦜙𥃼𣫟𢓂𠺥𩽞𨥁𧌣𥴆𤛩𣃌𡪯𠒒𩕊𧼭𦤐𥋳𣳖𢚹𡂜𪅔𨬷𧔚𥻽𤣠𣋃𡲥𠚈𩝁𨄤𦬇𥓪𣻌𢢯𡊒𪍋𨴮𧜑𦃴𤫖𣒹𡺜𠡿𩤸𨌛𦳽𥛠𤃃𢪦𡒉𪕂𨼥𧤇𦋪𤳍𣚰𢂓𠩶𩬮", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("EnteringIntlChars2", @"𧊅𥱨𤙋𣀮𡨐𠏳𩒬𧺏𦡲𥉕𣰷𢘚𠿽𪂶𨪙𧑼𥹞𤡁𣈤𡰇𠗪𩚣𨂆𦩨𥑋𣸮𢠑𡇴𪊭𨲏𧙲𦁕𤨸𣐛𡷾𠟡𩢙𨉼𦱟𥙂𤀥𢨈𡏪𪒣𨺆𧡩𦉌𤰯𣘑𡿴𠧗𩪐𨑳𦹖𥠹𤈛𢯾𡗡𪚚𩁽𧩠𦑂𤸥𣠈𢇫𠯎𩲇𨙪𧁌𥨯𤐒𢷵𡟘𠆻𩉳𧱖𦘹𥀜𣧿𢏢𠷄𩹽𨡠𧉃𥰦𤘉𢿬𡧎𠎱𩑪𧹍𦠰𥈓𣯵𢗘𠾻𪁴𨩗𧐺𥸜", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("EnteringIntlChars3", @"𢽵𡥘𠌺𩏳𧷖𦞹𥆜𣭿𢕡𠽄𩿽𨧠𧏃𥶦𤞉𣅫𡭎𠔱𩗪𧿍𦦰𥎒𣵵𢝘𡄻𪇴𨯗𧖹𥾜𤥿𣍢𡵅𠜨𩟡𨇃𦮦𥖉𣽬𢥏𡌲𪏪𨷍𧞰𦆓𤭶𣕙𡼼𠤞𩧗𨎺𦶝𥞀𤅣𢭅𡔨𪗡𨿄𧦧𦎊𤵬𣝏𢄲𠬕𩯎𨖱𦾔𥥶𤍙𢴼𡜟𠄂𩆻𧮝𦖀𤽣𣥆𢌩𠴌𩷅𨞧𧆊𥭭𤕐𢼳𡤖𠋸𩎱𧶔𦝷𥅚𣬽𢔟𠼂𩾻𨦞𧎁𥵤𤝇𣄩𡬌", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("EnteringIntlChars4", @"𥮦a𨟠z𠵄4𣥿M𦖹f𩇳N𡝘g𤎒S𦿌l𩰇T𢅫m𤶥Y𧧟r𪘚Y𢭾E𥞸K𡅠7𣶚P𦧔i𩘏P𡭳i𤞭U𧏨n𪀢)𢖆B𥇁G𠭨3𣞢L𦏝e𩀗M𡕻9𤆶R𦷰k𩨪S𡾏l𤯉X𧠃q𪐾X𢦢D𥗜]𨈖v𠝻1𣎵J𥿯c𨰪K𡆎7𣷈P𦨃i𩘽Q𡮡i", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("EnteringIntlChars5", @"𡘻9𤉵R𦺯k𩫪S𢁎l𤲈X𧣃q𪓽Y𢩡E𥚜J𡁃gtOyYeqMY9E6𣱽O𦢸h𩓲P𡩖i𤚑U𧋋n𩼅)𢑪A𥂤Z𧳞s𠉂y𦋀e𨻺L𡑞8𤂙Q𦳓j𩤍R𡹲k𥏞𦧻𨀘𩘵𠕼𡮚𣆷𤟔𥷱𧐎𨨫W𧛦p𪌡X𢢅D𥒿]𨃺v𠙞1𣊘I𥻓b𨬍J𡁱6𣲬O𦣦h𩔠P𡪄i𤚿U𧋹n𩼳)𢒘B𥃒Z𧴌s", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("CommonSurrogates1", @"𣏚𣏟𣑑𣑥𣕚", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("CommonSurrogates2", @"𠀋𠂢𠂤𠌫𠍱", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("CommonSurrogates3", @"𠦝𠦝𠦝𠦝𠦝", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("CommonSurrogates4", @"𡽶𤹪𦥑𧸐𨑕", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample1", @"!#)6=@Aa}~<", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample2", @"啊齄丂狛狜隣郎隣兀﨩ˊ▇█〞〡￤℡㈱‐ー﹡﹢﹫、〓ⅰⅹ⒈€㈠㈩ⅠⅫ！￣ぁんァヶΑ︴АЯаяāɡㄅㄩ─╋︵﹄︻︱︳︴ⅰⅹɑɡ〇〾⿻⺁䜣€", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample3", @"㐀㒣㕴㕵㙉㙊䵯䵰䶴䶵", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample4", @"𠀀𠀁𠀂𠀃𪛑𪛒𪛓𪛔𪛕𪛖", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample5", @"᠀᠐᠙ᠠᡷᢀᡨᡩᡪᡫ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample6", @"ༀཇཉཪཱྋ྾࿌࿏ྼྙ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample7", @"ꀀꒌꂋꂌꂍꂎꂔꂕ꒐꓆", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample8", @"،؟ئبتجدرشعەﭖﭙﯓﯿﺉﺒﻺﻼ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample9", @"ᥐᥥᥦᥧᥨᥭᥰᥱᥲᥴ", ClaimValueTypes.String, issuer, originalIssuer);
            yield return new Claim("STBSample10", @"ᄓᄕᇬᇌᇜᇱㄱㅣ가힝", ClaimValueTypes.String, issuer, originalIssuer);
        }

        public static IEnumerable<Claim> ClaimsPlus( IEnumerable<Claim> claims = null, SigningCredentials signingCredential = null, Lifetime lifetime = null, string issuer = null, string originalIssuer = null, string audience = null )
        {
            string thisIssuer = issuer ?? ClaimsIdentity.DefaultIssuer;
            string thisOriginalIssuer = originalIssuer ?? thisIssuer;

            if ( claims != null )
            {
                foreach ( Claim claim in claims ) yield return claim;
            }

            if ( signingCredential != null )
            {
                JwtHeader header = new JwtHeader( signingCredential );

                foreach ( string key in header.Keys )
                {
                    string value = header[key];
                    yield return new Claim( key, value, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
                }
            }

            if ( lifetime != null )
            {
                yield return new Claim( JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(lifetime.Created.Value ).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
                yield return new Claim( JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate( lifetime.Expires.Value ).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }

            if ( audience != null )
            {
                yield return new Claim( JwtRegisteredClaimNames.Aud, audience, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }

            if ( issuer != null )
            {
                yield return new Claim( JwtRegisteredClaimNames.Iss, issuer, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }
        }

        public static IEnumerable<Claim> JsonClaims( string issuer, string orginalIssuer )
        {
            JavaScriptSerializer js = new JavaScriptSerializer();
            string jsString = js.Serialize( Entity.Default );
            yield return new Claim( typeof( Entity ).ToString(), jsString, "JsonClaimType", issuer, orginalIssuer );
        }

        public static IEnumerable<Claim> GroupClaims(string issuer, string originalIssuer)
        {
            yield return new Claim("upn", "badams@dushyantgill.net", issuer, originalIssuer);
            yield return new Claim("family_name", "Adams", issuer, originalIssuer);
            yield return new Claim("unique_name", "badams@dushyantgill.net", issuer, originalIssuer);
            yield return new Claim("ver", "1.0", issuer, originalIssuer);
            yield return new Claim("aud", "0bb44690-eae0-4b2c-b2b1-64ac03098226", issuer, originalIssuer);
            yield return new Claim("iss", "https://sts.windows.net/5803816d-c4ab-4601-a128-e2576e5d6910/", issuer, originalIssuer); 
            yield return new Claim("groups", "c4324023-3424-4ba6-9320-1ce28431b113", issuer, originalIssuer);
            yield return new Claim("groups","08953f81-ffd6-44f9-887d-69855355ffbd", issuer, originalIssuer);
            yield return new Claim("groups", "694a55b2-ec4c-480d-8a7d-26d34ea9225b", issuer, originalIssuer);
            yield return new Claim("oid", "0c9545d0-a670-4628-8c1f-e90618a3b940", issuer, originalIssuer);
            yield return new Claim("nonce", "02f9c7ba-1720-4d46-b00f-6731fe2c4d14", issuer, originalIssuer);
            yield return new Claim("given_name", "Brad", issuer, originalIssuer);
            yield return new Claim("tid", "5803816d-c4ab-4601-a128-e2576e5d6910", issuer, originalIssuer);
            yield return new Claim("iat", "1403822988", issuer, originalIssuer);
            yield return new Claim("amr", "pwd", issuer, originalIssuer);
            yield return new Claim("sub", "355anlmMo6uvGyabeIqNqBTUJsEPdyijxouLjfmg8G8", issuer, originalIssuer);
        }

        /// <summary>
        /// Uses JwtSecurityTokenHandler.OutboundClaimTypeMap to map claimtype.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        public static Claim OutboundClaim( Claim claim )
        {
            Claim outboundClaim = claim;
            if ( JwtSecurityTokenHandler.OutboundClaimTypeMap.ContainsKey( claim.Type ) )
            {
                outboundClaim = new Claim( JwtSecurityTokenHandler.OutboundClaimTypeMap[claim.Type], claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer, claim.Subject );
                foreach ( KeyValuePair< string, string > kv in claim.Properties )
                {
                    outboundClaim.Properties.Add( kv );
                }
            }

            return outboundClaim;
        }

        /// <summary>
        /// Simulates that a claim arrived and was mapped, adds the short name property for any claims that would have been translated
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        public static Claim InboundClaim( Claim claim )
        {
            if ( JwtSecurityTokenHandler.OutboundClaimTypeMap.ContainsKey( claim.Type ) )
            {
                if ( JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( JwtSecurityTokenHandler.OutboundClaimTypeMap[claim.Type] ) )
                {
                    if ( !claim.Properties.ContainsKey( JwtSecurityTokenHandler.ShortClaimTypeProperty ) )
                    {
                        claim.Properties.Add( JwtSecurityTokenHandler.ShortClaimTypeProperty, JwtSecurityTokenHandler.OutboundClaimTypeMap[claim.Type] );
                    }
                }
            }

            return claim;
        }
    }

    /// <summary>
    /// Complex type. Used for testing roundtripping using complex claims.
    /// </summary>
    public class Entity
    {
        public static Entity Default
        {
            get
            {
                Entity entity = new Entity
                {
                    Address = new Address
                    {
                        Country = "Country",
                        Locality = "Locality",
                        Region = "Region"
                    },
                    Email = "email@email.com",
                    Email_Verified = false,
                    Exp = 1234567891,
                    FavoriteColors = new string[] { "blue", "red", "orange" },
                    Nothing = null,
                    pi = 3.14159,
                    Request = new Request
                    {
                        Acr = new Acr()
                        {
                            Values = new string[] { "urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze" }
                        },
                        AuthTime = new AuthTime()
                        {
                            Essential = false
                        },
                        NicKName = null
                    },
                    Urn = "urn:example:attributes"
                };

                return entity;
            }
        }

        public string Email { get; set; }
            
        public bool Email_Verified { get; set; }

        public string Urn { get; set; }

        public long   Exp { get; set; }

        public double pi  { get; set; }

        public string Nothing { get; set; }
            
        public string[] FavoriteColors { get; set; }

        public Address Address { get; set; }

        public Request Request { get; set; }
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class AuthTime
    {
        public bool Essential { get; set;}
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Acr
    {
        public string[] Values{ get; set;}
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Request
    {
        public string NicKName { get; set; }
            
        public AuthTime AuthTime { get; set; }
            
        public Acr Acr { get; set; }
    }

    /// <summary>
    /// Contained in Entity class to test complext claims
    /// </summary>
    public class Address
    {
        public string Locality { get; set; }
            
        public string Region   { get; set; }
            
        public string Country  { get; set; }
    }
}
