package cz.cvut.fit.cernama9.cracker.attacks;

import com.google.common.collect.Interner;
import com.google.common.math.BigIntegerMath;
import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 26.3.16.
 */
public class PollardPMinus1 implements RSAAttack
{
	private volatile boolean run;
	private AttackResult result;

	public void test(BigInteger p, BigInteger q)
	{
		begin(new SimpleRSAPublicKey(p, q));
	}

	@Override
	public void begin(RSAPublicKey certificate)
	{
		run = true;
		final BigInteger n = certificate.getModulus();

		System.out.println("Testing n ~ " + n.bitLength() + " bits");

		int b = 2;
		BigInteger a = BigInteger.valueOf(2),
		k = BigInteger.valueOf(2);

		long startTime = System.nanoTime();

		while (run)
		{
			BigInteger d = a.modPow(k, n).subtract(BigInteger.ONE).gcd(n);

			if (d.equals(BigInteger.ONE))
			{
				b++;
				k = k.multiply(BigInteger.valueOf(b));
				continue;
			}
			else if (d.equals(n))
			{
				a = a.add(BigInteger.ONE);
				continue;
			}

			result = new AttackResult(n.divide(d),d);
			run = false;
		}

		long estimatedTime = System.nanoTime() - startTime;
		System.out.println("Cracking took us " + estimatedTime / 1e9 + "s");
		System.out.println("b=" + b +", a=" + a);

	}

	@Override
	public AttackResult getResult()
	{
		return result;
	}

	@Override
	public void stop()
	{
		run = false;
	}
}
