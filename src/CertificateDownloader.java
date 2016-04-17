import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 17.4.16.
 */
public class CertificateDownloader
{
	public static void main(String[] args) throws Exception
	{
		System.setProperty("javax.net.ssl.trustStore", "/home/martin/Desktop/CTU-BP/keystore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

		//sni.velox.ch nebude s false fungovat
		//fit.cvut.cz nebude s true fungovat
		//System.setProperty("jsse.enableSNIExtension", "false");


		URL destinationURL = new URL("https://crypto.stackexchange.com");
		HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
		try
		{
			conn.connect();
		}
		catch (Exception ex)
		{
			//Zajima nas jen ta prvni vyjimka
			/*while (ex.getCause() != null && !ex.getCause().equals(ex))
			{
				ex = (Exception)ex.getCause();
			}*/

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
			Certificate cert = certs[0];
			if (cert.getPublicKey() instanceof RSAPublicKey)
			{
				System.out.println("Modul: " + ((RSAPublicKey) cert.getPublicKey()).getModulus());
				System.out.println("Public Exponent: " + ((RSAPublicKey) cert.getPublicKey()).getPublicExponent());
			}
			else
			{
				System.out.println("Neni RSA cert: " + cert.getPublicKey().getAlgorithm());
			}
			//System.out.println("################################################################");
			//System.out.println("Certificate is: " + cert);
			if (cert instanceof X509Certificate)
			{
				System.out.println("Signature Algo:" + ((X509Certificate) cert).getSigAlgName());
				System.out.println("Issuer DN:" + ((X509Certificate) cert).getIssuerDN());
				System.out.println("Subject DN:" + ((X509Certificate) cert).getSubjectDN());
				try
				{
					((X509Certificate) cert).checkValidity();
					System.out.println("Certificate is active for current date");
				}
				catch (CertificateExpiredException cee)
				{
					System.out.println("Certificate is expired");
				}
			}
			else
			{
				System.err.println("Unknown certificate type: " + cert);
			}
		}
	}
}
