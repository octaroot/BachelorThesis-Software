package cz.cvut.fit.cernama9.scanner;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.FileAlreadyExistsException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.sql.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 17.4.16.
 */
public class CertificateDownloader
{
	/**
	 * Sets the thread pool-size & the number of workers
	 */
	private static int maxWorkers = 10;

	/**
	 * Sets-up the tables this program will need to store scan results and downlaoded certificates.
	 *
	 * @param connection SQLite connection
	 * @throws SQLException
	 */
	private static void prepareDatabaseTables(Connection connection) throws SQLException
	{
		//Setup tables for our usage
		Statement stmt = connection.createStatement();
		String sql = "CREATE TABLE `certificate` (" +
				"`id_certificate` TEXT NOT NULL UNIQUE," +
				"`public_exponent` TEXT," +
				"`modulus` TEXT," +
				"`modulus_bits` INTEGER," +
				"`signature_algo` TEXT NOT NULL," +
				"`issuer_dn` TEXT NOT NULL," +
				"`subject_dn` TEXT NOT NULL," +
				"`valid_from` TEXT NOT NULL," +
				"`valid_to` TEXT NOT NULL," +
				"`processed` INTEGER NOT NULL DEFAULT 0," +
				" PRIMARY KEY(id_certificate)" +
				");" +
				"CREATE TABLE `scan` (" +
				"`domain` TEXT NOT NULL UNIQUE," +
				"`error` TEXT," +
				"`id_certificate` INTEGER," +
				"PRIMARY KEY(domain)," +
				"FOREIGN KEY(`id_certificate`) REFERENCES certificate(id_certificate)" +
				");" +
				"CREATE TABLE `attack` (" +
				"`id_certificate` INTEGER NOT NULL," +
				"`attack` TEXT NOT NULL," +
				"`private_exponent` TEXT," +
				"`prime_p` TEXT," +
				"`prime_q` TEXT," +
				"PRIMARY KEY(id_certificate,attack)," +
				"FOREIGN KEY(`id_certificate`) REFERENCES certificate ( id_certificate )" +
				");";
		stmt.executeUpdate(sql);
		stmt.close();
	}

	/**
	 * Binds the data to a certificate PreparedStatement specified
	 *
	 * @param statement Statement to bind the data to
	 * @param response  CertificateResponse data source
	 * @param df        DateFormat to be used
	 * @return A ready-to-execute prepared statement, with the data bound
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws SQLException
	 */
	private static PreparedStatement prepareCertificateStatement(PreparedStatement statement,
	                                                             CertificateResponse response,
	                                                             DateFormat df)
			throws CertificateEncodingException, NoSuchAlgorithmException, SQLException
	{
		final X509Certificate certificate = response.getCertificate();
		final String thumbprint = getThumbPrint(certificate);

		statement.setString(1, thumbprint);
		if (certificate.getPublicKey() instanceof RSAPublicKey)
		{
			RSAPublicKey pubKey = (RSAPublicKey) certificate.getPublicKey();
			statement.setString(2, pubKey.getPublicExponent().toString());
			statement.setString(3, pubKey.getModulus().toString());
			statement.setInt(4, pubKey.getModulus().bitLength());
		}
		else
		{
			statement.setNull(2, Types.VARCHAR);
			statement.setNull(3, Types.VARCHAR);
			statement.setNull(4, Types.INTEGER);
		}

		statement.setString(5, certificate.getSigAlgName());
		statement.setString(6, certificate.getIssuerDN().toString());
		statement.setString(7, certificate.getSubjectDN().toString());
		statement.setString(8, df.format(certificate.getNotBefore()));
		statement.setString(9, df.format(certificate.getNotAfter()));

		return statement;
	}

	/**
	 * Binds the data to a scan PreparedStatement specified
	 *
	 * @param statement Statement to bind the data to
	 * @param response  CertificateResponse data source
	 * @param domain    The target domain
	 * @return A ready-to-execute prepared statement, with the data bound
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws SQLException
	 */
	private static PreparedStatement prepareScanStatement(PreparedStatement statement,
	                                                      CertificateResponse response,
	                                                      String domain)
			throws CertificateEncodingException, NoSuchAlgorithmException, SQLException
	{
		final X509Certificate certificate = response.getCertificate();

		statement.setString(1, domain);
		if (response.getException() != null)
		{
			statement.setString(2, response.getException().toString().replace(domain, "<host>"));
		}
		else
		{
			statement.setNull(2, Types.VARCHAR);
		}

		if (certificate != null)
		{
			statement.setString(3, getThumbPrint(certificate));
		}
		else
		{
			statement.setNull(3, Types.VARCHAR);
		}

		return statement;
	}

	/**
	 * Sets-up the SQLite database connection for futher use (Opens the database, creates tables)
	 *
	 * @param filename SQLite database filename
	 * @return A ready-to-use SQLite database connection with the tables set-up
	 * @throws SQLException
	 * @throws ClassNotFoundException
	 * @throws FileAlreadyExistsException
	 */
	private static Connection setupDatabase(String filename)
			throws SQLException, ClassNotFoundException, FileAlreadyExistsException
	{
		//Check whether we may overwrite something
		final File dbFile = new File(filename);

		//In case we do, stop program execution and inform the user
		if (dbFile.exists() && !dbFile.isDirectory())
		{
			throw new FileAlreadyExistsException("File \"" + filename + "\" already exists. Select another database output file.");
		}

		//Setup SQLite connection
		Class.forName("org.sqlite.JDBC");
		Connection sqlite = DriverManager.getConnection("jdbc:sqlite:" + filename);

		//Inform the user
		System.out.println("Opened database successfully");

		try
		{
			prepareDatabaseTables(sqlite);
		}
		catch (SQLException ex)
		{
			System.err.println("Unable to create database tables.");
			throw ex;
		}

		System.out.println("Created tables successfully");

		return sqlite;
	}

	/**
	 * Prints the correct usage of this program
	 */
	private static void printCorrectUsage()
	{
		System.err.println("Correct usage: java CertificateDownloader <sqlite-output-file>");
	}

	/**
	 * The main class
	 *
	 * @param args Program arguments
	 */
	public static void main(String[] args)
	{
		if (args.length != 1)
		{
			printCorrectUsage();
			System.exit(1);
		}

		//poresit ignorovani domen az do posledni oscanovane
		//nevim, jestli se da spolehnout na nejaky select, snad ano
		//az tu bude reader, tak to pujde
		final boolean continueFromLastTime = true;
		final String lastScannedDomain = null;

		//for development, in production this will be replaced with program arguments (stdin/input file)
		final String[] domainsToCheck = {"wrong.host.badssl.com",
		                                 "martincernac.cz",
		                                 "wiener.martincernac.cz",
		                                 "pollard.martincernac.cz",
		                                 "near-primes.martincernac.cz",
		                                 "toools.martincernac.cz",
		                                 "cvut.cz",
		                                 "cvut.cz",
		                                 "fit.cvut.cz",
		                                 "users.fit.cvut.cz",
		                                 "crypto.stackexchange.com",
		                                 "ashdahsjdkhajkdahsskjd.com"};


		//Get the path to bundled keystore containing CA root certificates from Mozilla Firefox 45
		final URL keystorePath = CertificateDownloader.class.getResource("/keystore.jks");

		//Prepare a date format for SQLite usage
		final TimeZone tz = TimeZone.getTimeZone("CEST");
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
		df.setTimeZone(tz);

		//Setup bundled truststore
		System.setProperty("javax.net.ssl.trustStore", keystorePath.getPath());
		System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

		//Create SQLite connection
		Connection sqlite = null;

		try
		{
			sqlite = continueFromLastTime ? checkDatabase(args[0]) : setupDatabase(args[0]);
		}
		catch (ClassNotFoundException ignored)
		{
			System.err.println("Unable to locate SQLite library");
			System.exit(1);
		}
		catch (FileAlreadyExistsException | FileNotFoundException ex)
		{
			System.err.println(ex.getMessage());
			System.exit(1);
		}
		catch (SQLException ex)
		{
			System.err.println("Unable to setup the database, SQL error: " + ex.getMessage());
			System.exit(1);
		}

		System.out.println("Database init completed. Starting the scan");

		try
		{
			final PreparedStatement newCertificateRecord = sqlite.prepareStatement("INSERT OR IGNORE INTO certificate (id_certificate, public_exponent, modulus, modulus_bits, signature_algo, issuer_dn, subject_dn, valid_from, valid_to) VALUES(?,?,?,?,?,?,?,?,?)"),
					newScanRecord = sqlite.prepareStatement("INSERT OR IGNORE INTO scan (domain, error, id_certificate) VALUES (?,?,?)");

			final ExecutorService executorService = Executors.newFixedThreadPool(maxWorkers);
			final Semaphore semaphore = new Semaphore(maxWorkers);

			for (final String domain : domainsToCheck)
			{
				try
				{
					semaphore.acquire();
				}
				catch (InterruptedException ignored) { }
				executorService.submit((Runnable) () -> {
					final CertificateResponse response;

					System.out.println(domain);
					try
					{
						response = processDomain("https://" + domain);
					}
					catch (MalformedURLException ignored)
					{
						System.err.println("Unable to scan domain \"" + domain + "\"");
						semaphore.release();
						return;
					}

					if (response.getCertificate() != null)
					{
						try
						{
							prepareCertificateStatement(newCertificateRecord, response, df).execute();
						}
						catch (NoSuchAlgorithmException ignored)
						{
							System.err.println("Unable to calculate the thumbprint of the certificate (SHA-1)");
							semaphore.release();
							return;
						}
						catch (CertificateEncodingException ignored)
						{
							System.err.println("Unable to calculate the thumbprint of the certificate, because the certificate is corrupt");
							semaphore.release();
							return;
						}
						catch (SQLException ex)
						{
							System.err.println("Unable to save certificate data, SQL error: " + ex.getMessage());
							semaphore.release();
							return;
						}
					}

					try
					{
						prepareScanStatement(newScanRecord, response, domain).execute();
					}
					catch (NoSuchAlgorithmException ignored)
					{
						System.err.println("Unable to calculate the thumbprint of the certificate (SHA-1)");
						semaphore.release();
						return;
					}
					catch (CertificateEncodingException ignored)
					{
						System.err.println("Unable to calculate the thumbprint of the certificate, because the certificate is corrupt");
						semaphore.release();
						return;
					}
					catch (SQLException ex)
					{
						System.err.println("Unable to save scan data, SQL error: " + ex.getMessage());
						semaphore.release();
						return;
					}

					semaphore.release();
				});

			}

			System.out.println("=== All tasks submitted, awaiting termination ===");

			while (semaphore.availablePermits() != maxWorkers)
			{
				Thread.sleep(1000);
			}

			System.out.println("Terminating");

			executorService.shutdownNow();

			System.out.println("Shutdown complete");

		}
		catch (SQLException ex)
		{
			System.err.println("Unable to setup prepared statements, SQL error: " + ex.getMessage());
			System.exit(1);
		}
		catch (InterruptedException ignored) {}

		System.out.println("Scan finished. Total number of domains scanned: " + domainsToCheck.length + ". Closing database connection.");

		try
		{
			sqlite.close();
		}
		catch (SQLException ignored) { }
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
		final URL domainName = new URL(domain);
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
	public static X509Certificate downloadCertificate(URL domain, boolean verifyCertificate)
			throws CertificateException, IOException, KeyManagementException, NoSuchAlgorithmException
	{
		HttpsURLConnection connection = verifyCertificate ? generateSafeConnection(domain) : generateUnsafeConnection(domain);
		connection.setConnectTimeout(5000);
		connection.setReadTimeout(10000);
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
	public static String getThumbPrint(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException
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
		char[] hexDigits = {'0',
		                    '1',
		                    '2',
		                    '3',
		                    '4',
		                    '5',
		                    '6',
		                    '7',
		                    '8',
		                    '9',
		                    'a',
		                    'b',
		                    'c',
		                    'd',
		                    'e',
		                    'f'};

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
	public static HttpsURLConnection generateUnsafeConnection(URL domain)
			throws NoSuchAlgorithmException, KeyManagementException, IOException
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
		connection.setHostnameVerifier((hostname, session) -> true);

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

	private static Connection checkDatabase(String filename)
			throws SQLException, ClassNotFoundException, FileNotFoundException
	{
		//Check whether we may overwrite something
		final File dbFile = new File(filename);

		//In case we do, stop program execution and inform the user
		if (!dbFile.exists() || dbFile.isDirectory() || !dbFile.canRead())
		{
			throw new FileNotFoundException("File \"" + filename + "\" not found or unreadable.");
		}

		//Setup SQLite connection
		Class.forName("org.sqlite.JDBC");
		Connection sqlite = DriverManager.getConnection("jdbc:sqlite:" + filename);

		//Inform the user
		System.out.println("Opened database successfully");

		try
		{
			Statement checkTableExistence = sqlite.createStatement();
			for (String tableName : new String[]{"attack",
			                                     "certificate",
			                                     "scan"})
			{
				final ResultSet resultSet = checkTableExistence.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='" + tableName + "';");
				if (!resultSet.next())
				{
					throw new IllegalArgumentException("The database file provided is missing required tables. Please check that it is indeed a database file created by the CertificateDownloader program");
				}
			}
		}
		catch (SQLException ex)
		{
			System.err.println("Unable to check database tables.");
			throw ex;
		}

		System.out.println("Successfully checked the tables");

		return sqlite;
	}
}
