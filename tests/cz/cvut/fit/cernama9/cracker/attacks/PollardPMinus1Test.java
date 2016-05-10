package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 20.4.16.
 */
public class PollardPMinus1Test
{
	@Test
	public void tooHard()
	{
		//takes about 20 minutes!!
		PollardPMinus1 pollard = new PollardPMinus1();
		//q-1 ~ 1009-smooth
		BigInteger q = new BigInteger("140295601414508771014055437422614114373107540709320504535980361499526387693956746041130138940567002038374428496717918341136734065764752171812324861256943786339385079892371189986510770249285707542024496493124056732004512673929197790434881791518194754860284346626445459329813253857924929943715520407728047359567"),
				//p-1 ~ 1009-smooth
				p = new BigInteger("147002449502770587691565828611684963167687304284981893810489757328026497000444888455156760091384771179505706282609449594816450719879739058668216511792124123763333704066407842228587493535795463681667248262722529911601316325698977425602927530555861561885546661869051454123129531773231451055651331507089456213273");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void twoKExample()
	{
		//cca ~1 min
		PollardPMinus1 pollard = new PollardPMinus1();
		//p-1 ~ 353-smooth
		BigInteger p = new BigInteger("89972811204097954593630349958521842930960606864238468354055552344532903039401242183603663650582292075770329638598535458282987761002642617391857756125563737303910856065646500534915514773178769835910449858523286767236978944128056013112895632074362786896740722740122431636447471273647859747500587153238569367501"),
				//q-1 ~ 179-smooth
				q = new BigInteger("288756685704541542465005650254158064180016009543166038858690957577780890944634444261907437919659158557499971156776944829628997673448786678647157937340892483492044967855575732169765356341564688571607538348443422916657625946960835148908175235610769050348432488751799142754354339128078991811723501821626034103501");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void oneKExample()
	{
		//cca ~ 16s
		PollardPMinus1 pollard = new PollardPMinus1();

		//p-1 ~ 547-smooth
		BigInteger p = new BigInteger("13123747107276546011123919763863704679872778686699232255072563895805668327036757286255507784698042140248095518370668492372691523838668695869745616107192137"),
				//q-1 ~ 523-smooth
				q = new BigInteger("13046501912940014498345368931963641717246348075702641430340316104159582285737148795013181008995703245350504271722009968024592051580084922020966315695975009");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void smallExample()
	{
		//dve 40-bitova cisla
		PollardPMinus1 pollard = new PollardPMinus1();
		BigInteger p = new BigInteger("756077174459"),
				q = new BigInteger("741030129527");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void tinyExample()
	{
		PollardPMinus1 pollard = new PollardPMinus1();
		BigInteger p = new BigInteger("178481"),
				q = new BigInteger("47");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void testIncrementingNumberA()
	{
		/**
		 * I first had to find a number N, that could be written in the form N=2^k - 1
		 * and in addition, it consisted of two distinct primes, which could not be written
		 * in the same form (2^k - 1). For example 2047 (2^11 - 1) = 23 * 89
		 */
		PollardPMinus1 pollard = new PollardPMinus1();
		BigInteger p = new BigInteger("23"),
				q = new BigInteger("89");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void mediumExample()
	{
		PollardPMinus1 pollard = new PollardPMinus1();
		BigInteger p = new BigInteger("229677293327050529539455808324399895831627"),
				q = new BigInteger("506529590893119356151076159125041504738545155983");

		pollard.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = pollard.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}
}