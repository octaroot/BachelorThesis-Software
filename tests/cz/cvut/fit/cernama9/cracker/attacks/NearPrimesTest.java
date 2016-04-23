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