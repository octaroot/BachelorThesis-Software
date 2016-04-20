package cz.cvut.fit.cernama9.cracker;

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
		this.p = p;
		this.q = q;
		this.e = e;
	}

	public SimpleRSAPublicKey(BigInteger p, BigInteger q)
	{
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
