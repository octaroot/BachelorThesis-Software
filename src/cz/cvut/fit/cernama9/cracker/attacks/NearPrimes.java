package cz.cvut.fit.cernama9.cracker.attacks;

import com.google.common.math.BigIntegerMath;
import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;

import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class NearPrimes implements RSAAttack
{
	private AttackResult result = null;

	public void test(RSAPublicKey publicKey)
	{
		run(publicKey);
	}

	@Override
	public void run(RSAPublicKey publicKey)
	{
		result = null;

		final BigInteger n = publicKey.getModulus();
		BigInteger guess = BigIntegerMath.sqrt(n, RoundingMode.CEILING), temp;

		temp = guess.pow(2).subtract(n);

		while (!Thread.currentThread().isInterrupted())
		{
			if (BigIntegerMath.sqrt(temp, RoundingMode.DOWN).pow(2).equals(temp))
			{
				final BigInteger b = BigIntegerMath.sqrt(temp, RoundingMode.UNNECESSARY),
						p = guess.subtract(b),
						q = guess.add(b);
				result = new AttackResult(p, q);
				return;
			}
			guess = guess.add(BigInteger.ONE);
			temp = guess.pow(2).subtract(n);
		}

	}

	@Override
	public AttackResult getResult()
	{
		return result;
	}
}
