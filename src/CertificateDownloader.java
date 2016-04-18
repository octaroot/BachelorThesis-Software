import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 17.4.16.
 */
public class CertificateDownloader
{
	public static void main(String[] args) throws Exception
	{
		URL url = CertificateDownloader.class.getResource("keystore.jks");

		System.setProperty("javax.net.ssl.trustStore", url.getPath());
		System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

		//sni.velox.ch nebude s false fungovat
		//fit.cvut.cz nebude s true fungovat
		//System.setProperty("jsse.enableSNIExtension", "false");


		//pro testovani se muze hodit https://badssl.com/
		URL destinationURL = new URL("https://crypto.stackexchange.com/");
		HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
		try
		{
			conn.connect();
		}
		catch (Exception ex)
		{
			//Zajima nas jen ta prvni vyjimka
			while (ex.getCause() != null && !ex.getCause().equals(ex))
			{
				ex = (Exception)ex.getCause();
			}

			//http://stackoverflow.com/questions/7615645/ssl-handshake-alert-unrecognized-name-error-since-upgrade-to-java-1-7-0
			if (ex.getMessage().equals("handshake alert:  unrecognized_name"))
			{
				throw new RuntimeException("Badly configured SNI-supporting server. Recheck later with -Djsse.enableSNIExtension=false");
			}
			throw ex;
		}
		Certificate[] certs = conn.getServerCertificates();
		System.out.println("nb = " + certs.length);

		if (certs.length > 0)
		{
			//zajima nas jen peer cert, chain jde mimo
			Certificate cert = certs[0];
			if (cert.getPublicKey() instanceof RSAPublicKey)
			{
				System.out.println("Modulus: " + ((RSAPublicKey) cert.getPublicKey()).getModulus());
				System.out.println("Modulus size: " + ((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength());
				System.out.println("Public Exponent: " + ((RSAPublicKey) cert.getPublicKey()).getPublicExponent());
			}
			else
			{
				System.out.println("Not a RSA-based cert: " + cert.getPublicKey().getAlgorithm());
			}

			//vsechny certy jsou x509 certy ... https://bugzilla.mozilla.org/show_bug.cgi?id=290029
			//ff jiny ani nepodporuje. simulujeme chovani ff (via truststore)
			if (!(cert instanceof X509Certificate))
			{
				System.err.println("Unknown certificate type: " + cert);
			}
			else
			{
				System.out.println("Signature Algo: " + ((X509Certificate) cert).getSigAlgName());
				System.out.println("Issuer DN: " + ((X509Certificate) cert).getIssuerDN());
				System.out.println("Subject DN: " + ((X509Certificate) cert).getSubjectDN());
				System.out.println("Thumbprint: " + getThumbPrint((X509Certificate) cert));
			}
		}
	}
	public static String getThumbPrint(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		return hexify(digest);

	}

	public static String hexify (byte bytes[]) {

		char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
		                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		StringBuilder buf = new StringBuilder(bytes.length * 2);

		for (byte aByte : bytes)
		{
			buf.append(hexDigits[(aByte & 0xf0) >> 4]);
			buf.append(hexDigits[aByte & 0x0f]);
		}

		return buf.toString();
	}
}
