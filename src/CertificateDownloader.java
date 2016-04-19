import javax.net.ssl.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 17.4.16.
 */
public class CertificateDownloader
{
	public static void main(String[] args) throws Exception
	{
		URL keystorePath = CertificateDownloader.class.getResource("keystore.jks");

		System.setProperty("javax.net.ssl.trustStore", keystorePath.getPath());
		System.setProperty("javax.net.ssl.trustStorePassword", "changeit");


		String[] domainsToCheck = {
				"https://wrong.host.badssl.com",
		        "https://martincernac.cz",
		        "https://toools.martincernac.cz",
		        "https://cvut.cz",
		        "https://fit.cvut.cz",
		        "https://users.fit.cvut.cz"
		};

		for (String domain : domainsToCheck)
		{
			CertificateResponse response = processDomain(domain);
			System.out.print(domain + ": ");
			if (response.getException() != null)
			{
				if (response.getCertificate() != null)
				{
					System.out.println("[BAD] " + response.getException().getMessage());
				}
				else
				{
					System.out.println("[ERR] " + response.getException().getMessage());
				}
			}
			else
			{
				System.out.println("[OK!]");
			}
		}

		/*if (cert != null)
		{
			//zajima nas jen peer cert, chain jde mimo
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

			System.out.println("Signature Algo: " + ((X509Certificate) cert).getSigAlgName());
			System.out.println("Issuer DN: " + ((X509Certificate) cert).getIssuerDN());
			System.out.println("Subject DN: " + ((X509Certificate) cert).getSubjectDN());
			System.out.println("Thumbprint: " + getThumbPrint((X509Certificate) cert));
		}*/
	}

	/**
	 * Process domain's certificate download. Attempt to download & verify the certificate and output the results
	 *
	 * @param domain The target domain
	 * @return A structure with both the certificate (if downloaded) and the exception (if there was one)
	 * @throws MalformedURLException
	 */
	public static CertificateResponse processDomain(String domain) throws MalformedURLException
	{
		URL domainName = new URL(domain);
		Certificate cert;
		try
		{
			//Attempt to download & validate the certificate
			cert = downloadCertificate(domainName, true);
			//Return it immediately, if successful
			return new CertificateResponse((X509Certificate) cert);
		}
		catch (Exception ex)
		{
			//The certificate didn't validate, or there was another issue

			//We are only interested in the original cause of failure
			while (ex.getCause() != null && !ex.getCause().equals(ex))
			{
				ex = (Exception) ex.getCause();
			}

			try
			{
				//Attempt to at least download the certificate, without validating it at all
				cert = downloadCertificate(domainName, false);
				//If successful, return the downloaded certificate and the validation exception
				return new CertificateResponse((X509Certificate) cert, ex);
			}
			catch (Exception ex2)
			{
				//If we can't even download the certificate with no checks, return the exception alone
				return new CertificateResponse(ex);
			}
		}
	}

	/**
	 * **
	 * Opens a SSL connection to domain specified and performs SSL handshake.
	 *
	 * @param domain The target domain name
	 * @return X509Certificate Peer certificate
	 * @throws CertificateParsingException  When no certificate has been provided
	 * @throws CertificateEncodingException When the certificate provided is not in standard X.509 format
	 * @throws IOException                  In other cases (e.g. unable to open the connection, untrusted certificate, expired certificate, ...)
	 */
	public static X509Certificate downloadCertificate(URL domain,
	                                                  boolean verifyCertificate) throws CertificateException, IOException, KeyManagementException, NoSuchAlgorithmException
	{
		HttpsURLConnection connection = (HttpsURLConnection) (verifyCertificate ? generateSafeConnection(domain) : generateUnsafeConnection(domain));

		Certificate[] certificates;
		//HttpsURLConnection provides full certificate validation, we only need to handle the exceptions
		try
		{
			connection.connect();
			certificates = connection.getServerCertificates();
		}
		finally
		{
			//In any case, we should always close the connection
			connection.disconnect();
		}

		//We only care about the server's certificate, the (now verified) chain does not interest us anymore
		if (certificates.length > 0)
		{
			if (!(certificates[0] instanceof X509Certificate))
			{
				//We don't support other formats than a standard X.509 certificate
				//This is because we are mimicking the behavior of Mozilla Firefox 45
				//which doesn't support other (e.g. OpenPGP based) keys.
				throw new CertificateEncodingException("Server's certificate is not in X.509 format");
			}

			return (X509Certificate) certificates[0];
		}
		else
		{
			throw new CertificateParsingException("No certificate provided");
		}

	}

	/**
	 * Generates a certificate "Thumbprint". This is used as a unique identifier of any given certificate. The value is calculated as a SHA1 hash of the certificate in DER format.
	 *
	 * @param cert The certificate to generate a thumbprint for
	 * @return Printable SHA1 hash in hexadecimal format
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 */
	public static String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		return hexify(digest);

	}

	/**
	 * Helper function to create a printable (human readable) version of the byte-array specified
	 *
	 * @param bytes The byte array to be converted into a human-readable form
	 * @return Human readable string of hex-digits, representing the specified byte-array
	 */
	public static String hexify(byte bytes[])
	{
		char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		StringBuilder buf = new StringBuilder(bytes.length * 2);

		for (byte aByte : bytes)
		{
			buf.append(hexDigits[(aByte & 0xf0) >> 4]);
			buf.append(hexDigits[aByte & 0x0f]);
		}

		return buf.toString();
	}

	/**
	 * Generates an unsafe HttpsURLConnection in such a way, that trusts all presented certificates.
	 *
	 * @param domain The target domain name
	 * @return An instance of HttpsURLConnection with all validations and checks disabled
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws IOException
	 */
	public static HttpsURLConnection generateUnsafeConnection(URL domain) throws NoSuchAlgorithmException, KeyManagementException, IOException
	{
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, new TrustManager[]{new X509TrustManager()
		{
			public java.security.cert.X509Certificate[] getAcceptedIssuers()
			{
				return null;
			}

			public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType)
			{

			}

			public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType)
			{
			}
		}}, null);

		HttpsURLConnection connection = (HttpsURLConnection) domain.openConnection();

		connection.setSSLSocketFactory(sc.getSocketFactory());
		connection.setHostnameVerifier(new HostnameVerifier()
		{
			public boolean verify(String hostname, SSLSession session)
			{
				return true;
			}
		});

		return connection;
	}

	/**
	 * Generates a regular, safe HttpsURLConnection that validates certificates
	 *
	 * @param domain The target domain name
	 * @return An instance of HttpsURLConnection with all validations and checks enabled
	 * @throws IOException
	 */
	public static HttpsURLConnection generateSafeConnection(URL domain) throws IOException
	{
		return (HttpsURLConnection) domain.openConnection();
	}
}
