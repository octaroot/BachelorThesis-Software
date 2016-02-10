import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author martin (cernama9@fit.cvut.cz)
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
		final BigInteger TWO = BigInteger.valueOf(2);
		final BigInteger n = certificate.getModulus();
		BigInteger guess = sqrt(n);

		System.out.println("Testing n = " + n);
		System.out.println("Squared n to " + guess);

		if (!guess.isProbablePrime(32))
		{
			guess = guess.nextProbablePrime();
			System.out.println("Wasn't prime, using " + guess + " instead");
		}

		long startTime = System.nanoTime();

		while (run)
		{
			if (n.remainder(guess).equals(BigInteger.ZERO))
			{
				System.out.println("lol 0wn3d");
				System.out.println("p=" + n.divide(guess) + ",q=" + guess);
				run = false;
			}
			guess = guess.add(TWO);
		}

		long estimatedTime = System.nanoTime() - startTime;
		System.out.println("Cracking took us " + estimatedTime / 1e9 + "s");

	}

	@Override
	public void stop()
	{
		run = false;
	}

	BigInteger sqrt(BigInteger n)
	{
		BigInteger a = BigInteger.ONE;
		BigInteger b = new BigInteger(n.shiftRight(5).add(new BigInteger("8")).toString());
		while (b.compareTo(a) >= 0)
		{
			BigInteger mid = new BigInteger(a.add(b).shiftRight(1).toString());
			if (mid.multiply(mid).compareTo(n) > 0) b = mid.subtract(BigInteger.ONE);
			else a = mid.add(BigInteger.ONE);
		}
		return a.subtract(BigInteger.ONE);
	}
}
