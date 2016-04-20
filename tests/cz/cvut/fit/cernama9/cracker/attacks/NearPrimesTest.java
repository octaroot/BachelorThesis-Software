package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
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
	public void extremelyNearPrimes()
	{
		NearPrimes np = new NearPrimes();
		BigInteger p = BigInteger.valueOf(7),
				q = BigInteger.valueOf(11);

		np.test(p, q);
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

		np.test(p,p);
		AttackResult result = np.getResult();

		assertNotNull(result);
		assertEquals(p, result.getP());
		assertEquals(p, result.getQ());
		assertNull(result.getD());
	}

}