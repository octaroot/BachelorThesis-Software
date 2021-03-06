package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.4.16.
 */
public class Wiener implements RSAAttack
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

		List<BigInteger> quotients = new ArrayList<>();
		List<BigInteger> remainders = new ArrayList<>();
		List<BigInteger> denominators = new ArrayList<>();

		int i = 2;

		//step 1 (i=0)
		BigInteger[] tempFraction = publicKey.getPublicExponent().divideAndRemainder(publicKey.getModulus());
		quotients.add(tempFraction[0]);
		remainders.add(tempFraction[1]);
		denominators.add(ONE);

		//step 2 (i=1)
		tempFraction = publicKey.getModulus().divideAndRemainder(remainders.get(0));
		quotients.add(tempFraction[0]);
		remainders.add(tempFraction[1]);
		denominators.add(quotients.get(1));

		while (!Thread.currentThread().isInterrupted())
		{
			if (remainders.get(i - 1).equals(ZERO))
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

		while (!Thread.currentThread().isInterrupted() && i < denominators.size())
		{
			final BigInteger cipher = message.modPow(publicKey.getPublicExponent(), publicKey.getModulus()),
					decipher = cipher.modPow(denominators.get(i), publicKey.getModulus());

			if (message.equals(decipher))
			{
				result = new AttackResult(denominators.get(i));
				return;
			}

			i++;
		}

	}

	@Override
	public AttackResult getResult() { return result; }
}