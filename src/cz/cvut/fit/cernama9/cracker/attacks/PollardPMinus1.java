package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 26.3.16.
 */
public class PollardPMinus1 implements RSAAttack
{
	private       AttackResult result;

	public void test(BigInteger p, BigInteger q)
	{
		run(new SimpleRSAPublicKey(p, q, null));
	}

	@Override
	public void run(RSAPublicKey publicKey)
	{
		result = null;
		final long startTime = System.nanoTime();

		final BigInteger n = publicKey.getModulus();

		int b = 2;
		BigInteger a = BigInteger.valueOf(2),
				k = BigInteger.valueOf(2);


		while (!Thread.currentThread().isInterrupted())
		{
			BigInteger d = a.modPow(k, n).subtract(BigInteger.ONE).gcd(n);

			if (d.equals(BigInteger.ONE))
			{
				b++;
				//if (b % 100 == 0) System.out.println("b = " + b);
				k = k.multiply(BigInteger.valueOf(b));
				continue;
			}
			else if (d.equals(n))
			{
				a = a.add(BigInteger.ONE);
				continue;
			}

			result = new AttackResult(n.divide(d), d);
			return;
		}

	}

	@Override
	public AttackResult getResult()
	{
		return result;
	}
}
