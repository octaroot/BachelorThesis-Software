package cz.cvut.fit.cernama9.cracker.attacks;

import com.google.common.math.BigIntegerMath;
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
	private volatile boolean run;

	public void test(BigInteger p, BigInteger q)
	{
		begin(new SimpleRSAPublicKey(p, q));
	}

	@Override
	public void begin(RSAPublicKey certificate)
	{
		run = true;
		final BigInteger n = certificate.getModulus();
		BigInteger guess = BigIntegerMath.sqrt(n, RoundingMode.CEILING), temp;

		System.out.println("Testing n = " + n);
		System.out.println("Squared n to " + guess);

		temp = guess.pow(2).subtract(n);
		System.out.println("Starting at " + guess + " and counting down");

		long startTime = System.nanoTime();

		while (run)
		{
			if (BigIntegerMath.sqrt(temp, RoundingMode.DOWN).pow(2).equals(temp))
			{
				System.out.println("lol 0wn3d");
				System.out.println("p=" + guess.subtract(BigIntegerMath.sqrt(temp, RoundingMode.UNNECESSARY)) + ",q=" + guess.add(BigIntegerMath.sqrt(temp, RoundingMode.UNNECESSARY)));
				run = false;
			}
			guess = guess.add(BigInteger.ONE);
			temp = guess.pow(2).subtract(n);
		}

		long estimatedTime = System.nanoTime() - startTime;
		System.out.println("Cracking took us " + estimatedTime / 1e9 + "s");

	}

	@Override
	public void stop()
	{
		run = false;
	}
}
