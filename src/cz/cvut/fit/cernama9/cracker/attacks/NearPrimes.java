package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.RSAAttack;
import cz.cvut.fit.cernama9.cracker.SimpleRSAPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class NearPrimes implements RSAAttack
{
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private volatile boolean run;

	public static BigInteger sqrt(BigInteger n)
	{
		if (n.signum() >= 0)
		{
			final int bitLength = n.bitLength();
			BigInteger root = BigInteger.ONE.shiftLeft(bitLength / 2);

			while (!isSqrt(n, root))
			{
				root = root.add(n.divide(root)).divide(TWO);
			}
			return root;
		}
		else
		{
			throw new ArithmeticException("square root of negative number");
		}
	}

	private static boolean isSqrt(BigInteger n, BigInteger root)
	{
		final BigInteger lowerBound = root.pow(2);
		final BigInteger upperBound = root.add(BigInteger.ONE).pow(2);
		return lowerBound.compareTo(n) <= 0 && n.compareTo(upperBound) < 0;
	}

	public void test(BigInteger p, BigInteger q)
	{
		begin(new SimpleRSAPublicKey(p, q));
	}

	@Override
	public void begin(RSAPublicKey certificate)
	{
		run = true;
		final BigInteger n = certificate.getModulus();
		BigInteger guess = sqrt(n), temp;

		System.out.println("Testing n = " + n);
		System.out.println("Squared n to " + guess);

		if (guess.pow(2).compareTo(n) < 0)
			guess = guess.add(BigInteger.ONE);

		temp = guess.pow(2).subtract(n);
		System.out.println("Starting at " + guess + " and counting down");

		long startTime = System.nanoTime();

		while (run)
		{
			if (sqrt(temp).pow(2).equals(temp))
			{
				System.out.println("lol 0wn3d");
				System.out.println("p=" + guess.subtract(sqrt(temp)) + ",q=" + guess.add(sqrt(temp)));
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
