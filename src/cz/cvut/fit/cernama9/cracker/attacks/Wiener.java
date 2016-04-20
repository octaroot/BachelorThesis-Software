package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.RSAAttack;
import cz.cvut.fit.cernama9.cracker.SimpleRSAPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.4.16.
 */
public class Wiener implements RSAAttack
{
	private volatile boolean run;

	public void test(SimpleRSAPublicKey pkey)
	{
		begin(pkey);
	}

	@Override
	public void begin(RSAPublicKey certificate)
	{
		run = true;

		List<BigInteger> quotients = new ArrayList<BigInteger>();
		List<BigInteger> remainders = new ArrayList<BigInteger>();
		List<BigInteger> denominators = new ArrayList<BigInteger>();

		long startTime = System.nanoTime();

		int i = 2;

		//step 1 (i=0)
		BigInteger[] tempFraction = certificate.getPublicExponent().divideAndRemainder(certificate.getModulus());
		quotients.add(tempFraction[0]);
		remainders.add(tempFraction[1]);
		denominators.add(BigInteger.ONE);

		//step 2 (i=1)
		tempFraction = certificate.getModulus().divideAndRemainder(remainders.get(0));
		quotients.add(tempFraction[0]);
		remainders.add(tempFraction[1]);
		denominators.add(quotients.get(1));

		while (run)
		{
			if (remainders.get(i - 1).equals(BigInteger.ZERO))
			{
				break;
			}
			final BigInteger[] fraction = remainders.get(i - 2).divideAndRemainder(remainders.get(i - 1));
			quotients.add(fraction[0]);
			remainders.add(fraction[1]);
			denominators.add(quotients.get(i).multiply(denominators.get(i - 1)).add(denominators.get(i - 2)));

			i++;
		}

		i = 0;

		final BigInteger message = BigInteger.valueOf(3);

		while (run && i < denominators.size())
		{
			final BigInteger cipher = message.modPow(certificate.getPublicExponent(), certificate.getModulus()),
					decipher = cipher.modPow(denominators.get(i), certificate.getModulus());

			if (message.equals(decipher))
			{
				System.out.println("lol 0wn3d");
				System.out.println("d=" + denominators.get(i));
				run = false;
			}

			i++;
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