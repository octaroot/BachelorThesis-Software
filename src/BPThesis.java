import java.math.BigInteger;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class BPThesis
{
	public static void main(String[] args)
	{
		NearPrimes np = new NearPrimes();
		//$ openssl prime -generate -bits 32
		BigInteger p = BigInteger.valueOf(4224292349L),
				q = BigInteger.valueOf(3337347023L);
		np.test(p, q);
	}
}
