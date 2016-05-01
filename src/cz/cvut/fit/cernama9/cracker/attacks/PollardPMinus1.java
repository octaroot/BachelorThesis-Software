package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import static java.math.BigInteger.ONE;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 26.3.16.
 */
public class PollardPMinus1 implements RSAAttack
{
	private AttackResult result;

	public void test(RSAPublicKey publicKey)
	{
		run(publicKey);
	}

	@Override
	public void run(RSAPublicKey publicKey)
	{
		result = null;
		final BigInteger n = publicKey.getModulus();

		int b = 2;
		BigInteger a = BigInteger.valueOf(2),
				k = BigInteger.valueOf(2);


		while (!Thread.currentThread().isInterrupted())
		{
			BigInteger d = a.modPow(k, n).subtract(ONE).gcd(n);

			if (d.equals(ONE))
			{
				b++;
				k = k.multiply(BigInteger.valueOf(b));
				continue;
			}
			else if (d.equals(n))
			{
				b = 2;
				k = BigInteger.valueOf(2);
				d = a = a.add(ONE);
				if (d.gcd(n).equals(ONE)) continue;
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
