import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class SimpleRSAPublicKey implements RSAPublicKey
{
	private BigInteger p, q;

	SimpleRSAPublicKey(BigInteger p, BigInteger q)
	{
		this.p = p;
		this.q = q;
	}

	@Override
	public BigInteger getPublicExponent()
	{
		return null;
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
