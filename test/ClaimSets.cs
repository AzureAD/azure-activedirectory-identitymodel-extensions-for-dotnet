//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;

using Claim = System.Security.Claims.Claim;
using ClaimsIdentity = System.Security.Claims.ClaimsIdentity;
using ClaimTypes = System.Security.Claims.ClaimTypes;
using ClaimValueTypes = System.Security.Claims.ClaimValueTypes;

namespace System.IdentityModel.Test
{
    public static class ClaimSets
    {
        public static string ActorIssuer = "http://www.GotJwt.com/Actor";

        static Claim _actor             = new Claim( JwtConstants.ReservedClaims.Actor, JwtTestTokens.Simple( ActorIssuer, ActorIssuer ).ToString() );
        static Claim _audience          = new Claim( JwtConstants.ReservedClaims.Audience, "audienceClaimSets.Value" );
        static Claim _badHeaderType     = new Claim( JwtConstants.ReservedHeaderParameters.Type, "BADDTYPE" );
        static Claim _expBadDateFormat  = new Claim( JwtConstants.ReservedClaims.ExpirationTime, "BADDATEFORMAT" );
        static Claim _issuedAt          = new Claim( JwtConstants.ReservedClaims.IssuedAt, "issuedatClaimSets.Value" );
        static Claim _issuer            = new Claim( JwtConstants.ReservedClaims.Issuer,   "issuerClaimSets.Value" );
        static Claim _jwtId             = new Claim( JwtConstants.ReservedClaims.JwtId, "jwtIdClaimSets.Value" );
        static Claim _nbfBadDateFormat  = new Claim( JwtConstants.ReservedClaims.NotBefore, "BADDATEFORMAT" );
        static Claim _notAfter          = new Claim( JwtConstants.ReservedClaims.ExpirationTime, EpochTime.GetIntDate( DateTime.UtcNow + TimeSpan.FromHours( 1 ) ).ToString() );
        static Claim _notBefore         = new Claim( JwtConstants.ReservedClaims.NotBefore, EpochTime.GetIntDate(DateTime.UtcNow).ToString() );
        static Claim _principal         = new Claim( JwtConstants.ReservedClaims.Principal, "princlipalClaimSets.Value" );
        static Claim _sub               = new Claim( JwtConstants.ReservedClaims.Subject, "Subject.Value" );
        static Claim _type              = new Claim( JwtConstants.ReservedClaims.Type,     "Type.Value" );
        
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

        public static IEnumerable<Claim> GlobalClaims( string issuer, string originalIssuer )
        {
            yield return new Claim( "Arabic1", @"ايشواريا", ClaimValueTypes.String, issuer, originalIssuer );
            yield return new Claim( "Arabic2", @"الراي", ClaimValueTypes.String, issuer, originalIssuer );
            yield return new Claim( "Turkish1", @"ığIŞiĞİşçöÇÖ", ClaimValueTypes.String, issuer, originalIssuer );
        }

//  </Replacement>
//  <!--<Replacement>
//    --><!--<Placeholder>VariationID</Placeholder>--><!--
//    <Value>Turkish2</Value>
//    --><!--<Placeholder>GlobalizedString</Placeholder>--><!--
//    <Value>ĞİşÖ</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<Placeholder>VariationID</Placeholder>-->
//    <Value>Greek1</Value>
//    <!--<Placeholder>GlobalizedString</Placeholder>-->
//    <Value>χαίρετε</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<Placeholder>VariationID</Placeholder>--><!--
//    <Value>Greek2</Value>
//    --><!--<Placeholder>GlobalizedString</Placeholder>--><!--
//    <Value>βραχώδης</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<Placeholder>VariationID</Placeholder>-->
//    <Value>Chinese1</Value>
//    <!--<Placeholder>GlobalizedString</Placeholder>-->
//    <Value>阿洛哈</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<Placeholder>VariationID</Placeholder>--><!--
//    <Value>Chinese2</Value>
//    --><!--<Placeholder>GlobalizedString</Placeholder>--><!--
//    <Value>洛矶</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<Placeholder>VariationID</Placeholder>-->
//    <Value>Japanese1</Value>
//    <!--<Placeholder>GlobalizedString</Placeholder>-->
//    <Value>アロハ</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<Placeholder>VariationID</Placeholder>--><!--
//    <Value>Japanese2</Value>
//    --><!--<Placeholder>GlobalizedString</Placeholder>--><!--
//    <Value>ロッキー</Value>
//  </Replacement>-->

  
//  <!--Inputs from http://devdiv/sites/ddglob/globtopics/unicode/default.aspx - Unicode CJK Ext A-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>ExtA1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>㐖㐗㐘㐙㐚㐛㐜㐝㐞㐟㐠㐡㐢㐣㐤㐥㐦㐧㐨㐩㐪㐫㐬㐭㐮㐯㐰㐱</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtA2</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>㱍㱎㱏㱐㱑㱒㱓㱔㱕㱖㱗㱘㱙㱚㱛㱜㱝㱞㱟㱠㱡㱢㱣㱤㱥㱦㱧㱨㱩㱪㱫㱬㱭㱮㱯㱰㱱㱲㱳㱴㱵㱶㱷</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtA3</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>䐧䐨䐩䐪䐫䐬䐭䐮䐯䐰䐱䐲䐳䐴䐵䐶䐷䐸䐹䐺䐻䐼䐽䐾䐿䑀䑁䑂</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtA4</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>䝰䝱䝲䝳䝴䝵䝶䝷䝸䝹䝺䝻䝼䝽䝾䝿䞀䞁䞂䞃䞄䞅䞆䞇䞈䞉䞊䞋䞌䞍䞎䞏䞐䞑䞒䞓䞔䞕䞖䞗䞘䞙䞚䞛䞜䞝䞞䞟䞠䞡䞢䞣䞤䞥䞦䞧䞨䞩䞪䞫䞬䞭䞮䞯䞰䞱䞲䞳䞴䞵䞶䞷䞸䞹䞺䞻䞼䞽䞾䞿䟀䟁䟂䟃䟄䟅䟆䟇䟈䟉䟊䟋䟌䟍䟎䟏䟐䟑䟒䟓䟔䟕䟖䟗䟘䟙䟚䟛䟜䟝䟞䟟䟠䟡䟢䟣䟤</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>ExtA5</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>䱘䱙䱚䱛䱜䱝䱞䱟䱠䱡䱢䱣䱤䱥䱦䱧䱨䱩䱪䱫䱬䱭䱮䱯䱰䱱䱲䱳䱴䱵䱶䱷䱸䱹䱺䱻䱼䱽䱾䱿䲀䲁䲂䲃䲄䲅䲆䲇䲈䲉䲊䲋䲌䲍䲎䲏䲐䲑䲒䲓䲔䲕䲖䲗䲘䲙䲚䲛䲜䲝䲞䲟䲠䲡䲢䲣䲤䲥䲦䲧䲨䲩䲪䲫䲬䲭䲮䲯䲰䲱䲲䲳䲴䲵䲶䲷䲸䲹䲺䲻䲼䲽䲾䲿䳀䳁䳂䳃䳄䳅䳆䳇䳈䳉䳊䳋䳌䳍䳎䳏䳐䳑䳒䳓䳔䳕䳖䳗䳘䳙䳚䳛䳜䳝䳞䳟䳠䳡䳢䳣䳤䳥䳦䳧䳨䳩䳪䳫䳬䳭䳮䳯䳰䳱䳲䳳䳴䳵䳶䳷䳸䳹䳺䳻䳼䳽䳾䳿䴀䴁䴂䴃䴄䴅䴆䴇䴈䴉䴊䴋䴌䴍䴎䴏䴐䴑䴒䴓䴔䴕䴖䴗䴘䴙䴚䴛䴜䴝䴞䴟䴠䴡䴢䴣䴤䴥䴦䴧䴨䴩䴪䴫䴬䴭䴮䴯䴰䴱䴲䴳䴴䴵䴶䴷䴸䴹䴺䴻䴼䴽䴾䴿䵀䵁䵂䵃䵄䵅䵆䵇䵈䵉䵊䵋䵌䵍䵎䵏䵐䵑䵒䵓䵔䵕䵖䵗䵘䵙䵚䵛䵜䵝䵞䵟䵠䵡䵢䵣䵤䵥䵦䵧䵨䵩䵪䵫䵬䵭䵮䵯䵰䵱䵲䵳䵴䵵䵶䵷䵸䵹䵺䵻䵼䵽䵾䵿䶀䶁䶂䶃䶄䶅䶆䶇䶈䶉䶊䶋䶌䶍䶎䶏䶐䶑䶒䶓䶔䶕䶖䶗䶘䶙䶚䶛䶜䶝䶞䶟䶠䶡䶢䶣䶤䶥䶦䶧</Value>
//  </Replacement>
  


//  <!--Inputs from http://devdiv/sites/ddglob/globtopics/unicode/default.aspx - Unicode CJK Ext B-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>ExtB1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𠘣𠘤𠘥𠘦𠘧𠘨𠘩𠘪𠘫𠘬𠘭𠘮𠘯𠘰𠘱𠘲𠘳𠘴𠘵𠘶𠘷𠘸𠘹𠘺𠘻𠘼𠘽𠘾𠘿𠙀</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtB2</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𥀿𥁀𥁁𥁂𥁃𥁄𥁅𥁆𥁇𥁈𥁉𥁊𥁋𥁌𥁍𥁎𥁏</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtB3</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𡴥𡴦𡴧𡴨𡴩𡴪𡴫𡴬𡴭𡴮𡴯𡴰𡴱𡴲𡴳𡴴𡴵𡴶𡴷𡴸𡴹𡴺</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>ExtB4</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𧴒𧴓𧴔𧴕𧴖𧴗𧴘𧴙𧴚𧴛𧴜𧴝𧴞𧴟𧴠𧴡𧴢𧴣𧴤𧴥𧴦𧴧𧴨𧴩𧴪𧴫𧴬𧴭𧴮𧴯𧴰𧴱𧴲𧴳𧴴𧴵𧴶𧴷𧴸𧴹𧴺𧴻𧴼𧴽𧴾𧴿𧵀𧵁𧵂𧵃𧵄𧵅𧵆𧵇𧵈𧵉𧵊𧵋𧵌𧵍𧵎𧵏𧵐𧵑</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>ExtB5</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𪚶𪚷𪚸𪚹𪚺𪚻𪚼𪚽𪚾𪚿𪛀𪛁𪛂𪛃𪛄𪛅𪛆𪛇𪛈𪛉𪛊𪛋𪛌𪛍𪛎𪛏𪛐𪛑𪛒𪛓𪛔𪛕𪛖</Value>
//  </Replacement>


//  <!--Inputs from http://devdiv/sites/ddglob/globtopics/unicode/default.aspx - Entering Intl Chars-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>EnteringIntlChars1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𠣁𩥺𨍝𦴿𥜢𤄅𢫨𡓋𪖄𨽧𧥉𦌬𤴏𣛲𢃕𠪸𩭰𨕓𦼶𥤙𤋼𢳟𡛁𠂤𩅝𧭀𦔣𤼆𣣩𢋋𠲮𩵧𨝊𧄭𥬐𤓲𢻕𡢸𠊛𩍔𧴷𦜙𥃼𣫟𢓂𠺥𩽞𨥁𧌣𥴆𤛩𣃌𡪯𠒒𩕊𧼭𦤐𥋳𣳖𢚹𡂜𪅔𨬷𧔚𥻽𤣠𣋃𡲥𠚈𩝁𨄤𦬇𥓪𣻌𢢯𡊒𪍋𨴮𧜑𦃴𤫖𣒹𡺜𠡿𩤸𨌛𦳽𥛠𤃃𢪦𡒉𪕂𨼥𧤇𦋪𤳍𣚰𢂓𠩶𩬮</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>EnteringIntlChars2</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𧊅𥱨𤙋𣀮𡨐𠏳𩒬𧺏𦡲𥉕𣰷𢘚𠿽𪂶𨪙𧑼𥹞𤡁𣈤𡰇𠗪𩚣𨂆𦩨𥑋𣸮𢠑𡇴𪊭𨲏𧙲𦁕𤨸𣐛𡷾𠟡𩢙𨉼𦱟𥙂𤀥𢨈𡏪𪒣𨺆𧡩𦉌𤰯𣘑𡿴𠧗𩪐𨑳𦹖𥠹𤈛𢯾𡗡𪚚𩁽𧩠𦑂𤸥𣠈𢇫𠯎𩲇𨙪𧁌𥨯𤐒𢷵𡟘𠆻𩉳𧱖𦘹𥀜𣧿𢏢𠷄𩹽𨡠𧉃𥰦𤘉𢿬𡧎𠎱𩑪𧹍𦠰𥈓𣯵𢗘𠾻𪁴𨩗𧐺𥸜</Value>
//  </Replacement>
//    <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>EnteringIntlChars3</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𢽵𡥘𠌺𩏳𧷖𦞹𥆜𣭿𢕡𠽄𩿽𨧠𧏃𥶦𤞉𣅫𡭎𠔱𩗪𧿍𦦰𥎒𣵵𢝘𡄻𪇴𨯗𧖹𥾜𤥿𣍢𡵅𠜨𩟡𨇃𦮦𥖉𣽬𢥏𡌲𪏪𨷍𧞰𦆓𤭶𣕙𡼼𠤞𩧗𨎺𦶝𥞀𤅣𢭅𡔨𪗡𨿄𧦧𦎊𤵬𣝏𢄲𠬕𩯎𨖱𦾔𥥶𤍙𢴼𡜟𠄂𩆻𧮝𦖀𤽣𣥆𢌩𠴌𩷅𨞧𧆊𥭭𤕐𢼳𡤖𠋸𩎱𧶔𦝷𥅚𣬽𢔟𠼂𩾻𨦞𧎁𥵤𤝇𣄩𡬌</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>EnteringIntlChars4</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𥮦a𨟠z𠵄4𣥿M𦖹f𩇳N𡝘g𤎒S𦿌l𩰇T𢅫m𤶥Y𧧟r𪘚Y𢭾E𥞸K𡅠7𣶚P𦧔i𩘏P𡭳i𤞭U𧏨n𪀢)𢖆B𥇁G𠭨3𣞢L𦏝e𩀗M𡕻9𤆶R𦷰k𩨪S𡾏l𤯉X𧠃q𪐾X𢦢D𥗜]𨈖v𠝻1𣎵J𥿯c𨰪K𡆎7𣷈P𦨃i𩘽Q𡮡i</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>EnteringIntlChars5</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𡘻9𤉵R𦺯k𩫪S𢁎l𤲈X𧣃q𪓽Y𢩡E𥚜J𡁃gtOyYeqMY9E6𣱽O𦢸h𩓲P𡩖i𤚑U𧋋n𩼅)𢑪A𥂤Z𧳞s𠉂y𦋀e𨻺L𡑞8𤂙Q𦳓j𩤍R𡹲k𥏞𦧻𨀘𩘵𠕼𡮚𣆷𤟔𥷱𧐎𨨫W𧛦p𪌡X𢢅D𥒿]𨃺v𠙞1𣊘I𥻓b𨬍J𡁱6𣲬O𦣦h𩔠P𡪄i𤚿U𧋹n𩼳)𢒘B𥃒Z𧴌s</Value>
//  </Replacement>
  
  
//  <!--Inputs from http://devdiv/sites/ddglob/globtopics/unicode/default.aspx - Common Surrogates-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>CommonSurrogates1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𣏚𣏟𣑑𣑥𣕚</Value>
//  </Replacement>
//  <!--<Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>CommonSurrogates2</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𠀋𠂢𠂤𠌫𠍱</Value>
//  </Replacement>
//  <Replacement>
//    --><!--<placeholder>VariationID</placeholder>--><!--
//    <Value>CommonSurrogates3</Value>
//    --><!--<placeholder>GlobalizedString</placeholder>--><!--
//    <Value>𠦝𠦝𠦝𠦝𠦝</Value>
//  </Replacement>-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>CommonSurrogates4</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𡽶𤹪𦥑𧸐𨑕</Value>
//  </Replacement>


//  <!--Inputs from http://sharepointasia/sites/ProdReg/Knowledge%20Base/Forms/AllItems.aspx?RootFolder=%2Fsites%2FProdReg%2FKnowledge%20Base%2FSample%20Report - STBSample-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>!#)6=@Aa}~</Value>
//    <!--NOTE - had to remove " character because it wouldn't work correctly in TEF-->
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample2</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>啊齄丂狛狜隣郎隣兀﨩ˊ▇█〞〡￤℡㈱‐ー﹡﹢﹫、〓ⅰⅹ⒈€㈠㈩ⅠⅫ！￣ぁんァヶΑ︴АЯаяāɡㄅㄩ─╋︵﹄︻︱︳︴ⅰⅹɑɡ〇〾⿻⺁䜣€</Value>
//    <!--NOTE - there are some boxes shown here, but the characters are correct, but they won't display properly unless viewed using the SimSun font-->
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample3</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>㐀㒣㕴㕵㙉㙊䵯䵰䶴䶵</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample4</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>𠀀𠀁𠀂𠀃𪛑𪛒𪛓𪛔𪛕𪛖</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample5</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>᠀᠐᠙ᠠᡷᢀᡨᡩᡪᡫ</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample6</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>ༀཇཉཪཱྋ྾࿌࿏ྼྙ</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample7</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>ꀀꒌꂋꂌꂍꂎꂔꂕ꒐꓆</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample8</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>،؟ئبتجدرشعەﭖﭙﯓﯿﺉﺒﻺﻼ</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample9</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>ᥐᥥᥦᥧᥨᥭᥰᥱᥲᥴ</Value>
//  </Replacement>
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>STBSample10</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>ᄓᄕᇬᇌᇜᇱㄱㅣ가힝</Value>
//  </Replacement>


//  <!--Inputs from http://devdiv/sites/ddglob/qa/Shared%20Documents/Unicode%20Surrogates/Unicode_risky_charFE.mht - RiskyEA-->
//  <Replacement>
//    <!--<placeholder>VariationID</placeholder>-->
//    <Value>RiskyEA1</Value>
//    <!--<placeholder>GlobalizedString</placeholder>-->
//    <Value>ᄀᄩᄽᄨᄼ〤〻〩ㄺㅟ㈡㉻㌀㍻簀臿㠀㻿㕝뀀넿롞𧀀𧰦𧘬</Value>
//  </Replacement>
  
//</Replacements>
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
                yield return new Claim( JwtConstants.ReservedClaims.NotBefore, EpochTime.GetIntDate(lifetime.Created.Value ).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
                yield return new Claim( JwtConstants.ReservedClaims.ExpirationTime, EpochTime.GetIntDate( lifetime.Expires.Value ).ToString(), ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }

            if ( audience != null )
            {
                yield return new Claim( JwtConstants.ReservedClaims.Audience, audience, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }

            if ( issuer != null )
            {
                yield return new Claim( JwtConstants.ReservedClaims.Issuer, issuer, ClaimValueTypes.String, thisIssuer, thisOriginalIssuer );
            }
        }

        public static IEnumerable<Claim> JsonClaims( string issuer, string orginalIssuer )
        {
            JavaScriptSerializer js = new JavaScriptSerializer();
            string jsString = js.Serialize( Entity.Default );
            yield return new Claim( typeof( Entity ).ToString(), jsString, "JsonClaimType", issuer, orginalIssuer );
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

    public class AuthTime
    {
        public bool Essential { get; set;}
    }

    public class Acr
    {
        public string[] Values{ get; set;}
    }

    public class Request
    {
        public string NicKName { get; set; }
            
        public AuthTime AuthTime { get; set; }
            
        public Acr Acr { get; set; }
    }
        
    public class Address
    {
        public string Locality { get; set; }
            
        public string Region   { get; set; }
            
        public string Country  { get; set; }
    }
}
