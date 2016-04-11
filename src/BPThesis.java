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
		Wiener wiener = new Wiener();

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

		//p,q are 1024 bits, 2048 bit RSA modul
		p = new BigInteger("164634754624328802036294307610218133645985670740322764394133351376661620667807025915396282510335339603043492418476164116338138014905443659519418019488674850851014416098959214321871989465258905838991412914799310545012267151796775858141583397200919670826520198685852976375607704857769607568199455475129935991259");
		q = new BigInteger("153851225251040219779177968642958412726283841865253846613036163504037248192097265323521224532746664860129162970433466131527870254317544847924848667490554628401719684962993115548534984812010722987033965974390276278818611064174586153333011991365577837916566597465452963062956465141139033767913573596559384144839");
		BigInteger e = new BigInteger("11260877241727367648742811762227297628677999359275065753318137627101876897334323959637322468353063864328309995692310456329948910344114156557351100433249876966506924530209159833063050423799099396429937714772141425427898171353247252527012290711550648521491848811836565678487230741667453931777924118767947187320935640306357731280692704204879628864292282240153208662115595956606474818446513563417849662768028599179233828996970489795813035564601959564079827104585519055380504764878147207623258698374076771637904632896702358895363037310834170589566265984554819079952671710984834441889718783894360798617182914877500974127365");

		System.out.println("===\nWiener:");

		wiener.test(new SimpleRSAPublicKey(p, q, e));


	}
}
