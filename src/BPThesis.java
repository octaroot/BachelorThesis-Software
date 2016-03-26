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
		PollardPMinus1 pollard = new PollardPMinus1();

		//$ openssl prime -generate -bits 32
		//$ factor 1419262
		//1419262: 2 13 13 13 17 19

		BigInteger p = new BigInteger("3234903317"),
				q = new BigInteger("1419263");

		System.out.println("===\nPollardPMinus1:");

		pollard.test(p, q);

		//$ openssl prime -generate -bits 32
		//$ openssl prime -generate -bits 32
		p = new BigInteger("3234903317");
		q = new BigInteger("3332152829");

		System.out.println("===\nNearPrimes:");

		np.test(p, q);

	}
}
