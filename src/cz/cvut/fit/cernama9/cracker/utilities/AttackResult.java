package cz.cvut.fit.cernama9.cracker.utilities;

import java.math.BigInteger;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 20.4.16.
 */
public class AttackResult
{
	private final BigInteger p, q, d;

	public AttackResult(BigInteger p, BigInteger q)
	{
		this.p = p;
		this.q = q;
		this.d = null;
	}

	public AttackResult(BigInteger d)
	{
		this.p = null;
		this.q = null;
		this.d = d;
	}

	public BigInteger getD()
	{
		return d;
	}

	public BigInteger getQ()
	{
		return q;
	}

	public BigInteger getP()
	{
		return p;
	}
}
