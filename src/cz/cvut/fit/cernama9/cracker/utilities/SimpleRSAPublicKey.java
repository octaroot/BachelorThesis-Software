package cz.cvut.fit.cernama9.cracker.utilities;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class SimpleRSAPublicKey implements RSAPublicKey
{
	private BigInteger n, e;

	public SimpleRSAPublicKey(BigInteger p, BigInteger q, BigInteger e)
	{
		if (p.signum() < 1 || p.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Prime p cannot be <= 1");

		if (q.signum() < 1 || q.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Prime q cannot be <= 1");

		if (e != null)
		{
			if (e.signum() < 1 || e.equals(BigInteger.ONE))
				throw new IllegalArgumentException("Public exponent e cannot be <= 1");

			BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

			if (!e.gcd(phi).equals(BigInteger.ONE))
				throw new IllegalArgumentException("Public exponent e has no multiplicative inverse (given p,q)");
		}

		this.n = p.multiply(q);
		this.e = e;
	}

	public SimpleRSAPublicKey(BigInteger n, BigInteger e)
	{
		if (n.signum() < 1 || n.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Modulus n cannot be <= 1");

		if (e != null)
		{
			if (e.signum() < 1 || e.equals(BigInteger.ONE))
				throw new IllegalArgumentException("Public exponent e cannot be <= 1");
		}

		this.e = e;
		this.n = n;
	}

	@Override
	public BigInteger getPublicExponent()
	{
		return e;
	}

	@Override
	public String getAlgorithm()
	{
		return null;
	}

	@Override
	public String getFormat()
	{
		return null;
	}

	@Override
	public byte[] getEncoded()
	{
		return new byte[0];
	}

	@Override
	public BigInteger getModulus()
	{
		return n;
	}
}
