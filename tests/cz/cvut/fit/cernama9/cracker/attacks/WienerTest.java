package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 20.4.16.
 */
public class WienerTest
{
	@Test
	public void tinyModulusAndTinyPrivateExponent()
	{
		Wiener wiener = new Wiener();

		BigInteger p = BigInteger.valueOf(149),
				q = BigInteger.valueOf(41),
				e = BigInteger.valueOf(3947),
				d = BigInteger.valueOf(3);

		wiener.test(new SimpleRSAPublicKey(p, q, e));

		AttackResult result = wiener.getResult();

		assertNotNull(result);
		assertEquals(result.getD(), d);
		assertNull(result.getP());
		assertNull(result.getQ());
	}

	@Test
	public void tinyModulusAndLargePrivateExponent()
	{
		Wiener wiener = new Wiener();

		BigInteger p = BigInteger.valueOf(31),
				q = BigInteger.valueOf(41),
				e = BigInteger.valueOf(11),
				d = BigInteger.valueOf(1091);

		wiener.test(new SimpleRSAPublicKey(p, q, e));

		AttackResult result = wiener.getResult();

		assertNull(result);
	}

	@Test
	public void Modulus128bitAndTinyPrivateExponent()
	{
		Wiener wiener = new Wiener();

		BigInteger p = new BigInteger("274070111459752436218515801485229965669"),
				q = new BigInteger("298119098048033004402781737212102295227"),
				e = new BigInteger("54470356286870180306122421238060749065235351649140923774915773848410653533979"),
				d = BigInteger.valueOf(3);

		wiener.test(new SimpleRSAPublicKey(p, q, e));

		AttackResult result = wiener.getResult();

		assertNotNull(result);
		assertEquals(result.getD(), d);
		assertNull(result.getP());
		assertNull(result.getQ());
	}

	@Test
	public void Modulus2kAndSmallPrivateExponent()
	{
		Wiener wiener = new Wiener();

		BigInteger p = new BigInteger("164634754624328802036294307610218133645985670740322764394133351376661620667807025915396282510335339603043492418476164116338138014905443659519418019488674850851014416098959214321871989465258905838991412914799310545012267151796775858141583397200919670826520198685852976375607704857769607568199455475129935991259"),
				q = new BigInteger("153851225251040219779177968642958412726283841865253846613036163504037248192097265323521224532746664860129162970433466131527870254317544847924848667490554628401719684962993115548534984812010722987033965974390276278818611064174586153333011991365577837916566597465452963062956465141139033767913573596559384144839"),
				e = new BigInteger("11260877241727367648742811762227297628677999359275065753318137627101876897334323959637322468353063864328309995692310456329948910344114156557351100433249876966506924530209159833063050423799099396429937714772141425427898171353247252527012290711550648521491848811836565678487230741667453931777924118767947187320935640306357731280692704204879628864292282240153208662115595956606474818446513563417849662768028599179233828996970489795813035564601959564079827104585519055380504764878147207623258698374076771637904632896702358895363037310834170589566265984554819079952671710984834441889718783894360798617182914877500974127365"),
				d = new BigInteger("31321321332313213");

		wiener.test(new SimpleRSAPublicKey(p, q, e));

		AttackResult result = wiener.getResult();

		assertNotNull(result);
		assertEquals(result.getD(), d);
		assertNull(result.getP());
		assertNull(result.getQ());
	}

	@Test
	public void Modulus2kAndMediumPrivateExponent()
	{
		Wiener wiener = new Wiener();

		BigInteger p = new BigInteger("184dc8b9aab29cf5193472426e92163e41170637583b1ea2c50ae04513ae42e64281a51838d20051a5dbd1a6bd3e21906828f7768cad0b20a3af1ed8af1fd69b74e53c8d94d002774ef463b7872558bfa7b71315d29bc0268f5f60701f47ac247bc5fc713ad399f579d64dcea485c165443277da0626889cb84ab038870a41a37", 16),
				q = new BigInteger("1561b2615b9f35aa908c97cc5bf271e885942fcec28c071c8660ec6f3c0a6ec710e85a20bda689576b346c917df8782f43d7ecc1897a273a6c49b9e25fef4b5c72f317135dc97f554b1d1b22cf026b28e26094003468d2ecc12715e2ad02bcc371fd2766b3a3c667c86856669a30c9cf5cad1174e0c968070edbcab9f236282f5", 16),
				e = new BigInteger("f70b3bd74801a25eccbde24e01b077677e298391d4197b099a6f961244f04314da7de144dd69a8aa84686bf4ddbd14a6344bbc315218dbbaf29490a44e42e5c4a2a4e76b8101a5ca82351c07b4cfd4e08038c8d5573a827b227bce515b70866724718ec2ac03359614cdf43dd88f1ac7ee453917975a13c019e620e531207692224009c75eaef11e130f8e54cce31e86c84e9366219ae5c250853be145ea87dcf37aa7ece0a994195885e31ebcd8fe742df1cd1370c95b6684ab6c37e84762193c27dd34c3cf3f5e69957b8338f9143a0052c9381d9e2ecb9ef504c954b453f57632705ed44b28a4b5cbe61368e485da6af2dfc901e45868cdd5006913f338a3", 16),
				d = new BigInteger("66bee59fd0ff38daa47d219ca3837b8104682139b2ae3f7f5e117b319418cd5e9954ded33d417c1395bb73685a871c35dbc8f01cb2594f06be7654bbea1f3a23", 16);

		wiener.test(new SimpleRSAPublicKey(p, q, e));

		AttackResult result = wiener.getResult();

		assertNotNull(result);
		assertEquals(result.getD(), d);
		assertNull(result.getP());
		assertNull(result.getQ());
	}
}