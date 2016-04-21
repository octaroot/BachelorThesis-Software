package cz.cvut.fit.cernama9.cracker.utilities;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 20.4.16.
 */
public class SimpleRSAPublicKeyTest
{
	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void modulusFromPrimesWithoutPublicExponent()
	{
		BigInteger p = new BigInteger("5"),
				q = new BigInteger("3");

		SimpleRSAPublicKey publicKey = new SimpleRSAPublicKey(p, q, null);
		assertEquals(publicKey.getModulus(), p.multiply(q));
		assertNull(publicKey.getPublicExponent());
	}


	@Test
	public void modulusFromPrimesWithPublicExponent()
	{
		BigInteger p = new BigInteger("5"),
				q = new BigInteger("3"),
				e = new BigInteger("7");

		SimpleRSAPublicKey publicKey = new SimpleRSAPublicKey(p, q, e);
		assertEquals(publicKey.getModulus(), p.multiply(q));
		assertEquals(publicKey.getPublicExponent(), e);
	}

	@Test
	public void badPrimes()
	{
		BigInteger p = new BigInteger("5"),
				q = new BigInteger("3"),
				negativeNumber = new BigInteger("-5");

		exception.expect(IllegalArgumentException.class);

		new SimpleRSAPublicKey(p, negativeNumber, null);
		new SimpleRSAPublicKey(negativeNumber, p, null);
		new SimpleRSAPublicKey(p, BigInteger.ONE, null);
		new SimpleRSAPublicKey(BigInteger.ONE, p, null);

		new SimpleRSAPublicKey(p, q, negativeNumber);
		new SimpleRSAPublicKey(p, q, BigInteger.ONE);

		//gcd=1 triggered
		new SimpleRSAPublicKey(p, q, BigInteger.valueOf(4));

	}

	@Test
	public void noModularInverse()
	{
		BigInteger p = new BigInteger("11"),
				q = new BigInteger("13"),
				e = new BigInteger("40");

		exception.expect(IllegalArgumentException.class);

		new SimpleRSAPublicKey(p, q, e);

	}
}