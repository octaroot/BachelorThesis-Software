import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 26.3.16.
 */
public class PollardPMinus1 implements RSAAttack
{
	private volatile boolean run;

	public static BigInteger factorial(BigInteger n)
	{
		BigInteger result = BigInteger.ONE;

		while (!n.equals(BigInteger.ZERO))
		{
			result = result.multiply(n);
			n = n.subtract(BigInteger.ONE);
		}

		return result;
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
		final BigInteger TWO = BigInteger.valueOf(2);

		System.out.println("Testing n = " + n);

		final BigInteger b = BigInteger.valueOf(19),
				k = factorial(b),
				kMinus1 = k.subtract(BigInteger.ONE);

		System.out.println("Smoothness bound = " + b);

		long startTime = System.nanoTime();

		while (run)
		{
			//a je z intervalu <2;n-1>
			BigInteger a = new BigInteger(n.bitLength(), new Random()).mod(n);
			if (a.compareTo(BigInteger.ONE) <= 0) a = TWO;

			BigInteger d = a.modPow(kMinus1, n).gcd(n);

			if (d.equals(BigInteger.ONE))
			{
				continue;
			}

			System.out.println("lol 0wn3d (a = " + a + ")");
			System.out.println("p=" + n.divide(d) + ",q=" + d);
			run = false;
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
