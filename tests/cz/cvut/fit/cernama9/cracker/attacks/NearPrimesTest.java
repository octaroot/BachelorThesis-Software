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
public class NearPrimesTest
{
	@Test
	public void tooHard()
	{
		NearPrimes np = new NearPrimes();
		BigInteger p = new BigInteger("171017241702401758957566440165192497397837085781468974906656228171708806865046273719136247588381313303779599369895703499879199368289230911907261715169587617543971853216629794977961438304114410582105219291511618914647566662890652466627878885517239996866771039517589816408083785249048105753274562460546923415533");
		BigInteger q = p.add(BigInteger.TEN.pow(158)).multiply(BigInteger.valueOf(2)).nextProbablePrime();

		np.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void twoKExample()
	{
		//lisi se cca v polovine (498. MSB)
		NearPrimes np = new NearPrimes();
		BigInteger p = new BigInteger("160830782557826086255408586193761971121442118372472145500301652795033947227766219916749120960126418797758852156198232377201612482273170099423459869540494384165050088833965082562383206437322563648927080789814938427704305067225148235449446755732287855514474365565009970367161518797526617298237257651887629848979");
		BigInteger q = new BigInteger("160830782557826086255408586193761971121442118372472145500301652795033947227766219916749120960126418797758852156198232377201612482273170099423459869540523384165050088833965082562383206437322563648927080789814938427704305067225148235449446755732287855514474365565009970367161518797526617298237257651887629849699");

		np.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());


	}

	@Test
	public void tinyExample()
	{
		NearPrimes np = new NearPrimes();
		BigInteger q = new BigInteger("756077174459"),
				p = new BigInteger("741030129527");

		np.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void extremelyNearPrimes()
	{
		NearPrimes np = new NearPrimes();
		BigInteger p = BigInteger.valueOf(7),
				q = BigInteger.valueOf(11);

		np.test(new SimpleRSAPublicKey(p, q, null));
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(q, result.getQ());
		assertNull(result.getD());
	}

	@Test
	public void identicalPrimes()
	{
		NearPrimes np = new NearPrimes();
		BigInteger p = BigInteger.valueOf(17);

		np.test(new SimpleRSAPublicKey(p, p, null));
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(p, result.getQ());
		assertNull(result.getD());
	}

}