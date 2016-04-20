package cz.cvut.fit.cernama9.cracker.utilities;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class SimpleRSAPublicKey implements RSAPublicKey
{
	private BigInteger p, q, e;

	public SimpleRSAPublicKey(BigInteger p, BigInteger q, BigInteger e)
	{
		this (p,q);

		if (e.signum() < 1 || e.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Public exponent e cannot be <= 1");

		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		if (!e.gcd(phi).equals(BigInteger.ONE))
			throw new IllegalArgumentException("Public exponent e has no multiplicative inverse (given p,q)");

		this.p = p;
		this.q = q;
		this.e = e;
	}

	public SimpleRSAPublicKey(BigInteger p, BigInteger q)
	{
		if (p.signum() < 1 || p.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Prime p cannot be <= 1");

		if (q.signum() < 1 || q.equals(BigInteger.ONE))
			throw new IllegalArgumentException("Prime q cannot be <= 1");

		this.p = p;
		this.q = q;
		this.e = null;
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
		return p.multiply(q);
	}
}
