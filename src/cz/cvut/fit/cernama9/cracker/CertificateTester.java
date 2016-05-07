package cz.cvut.fit.cernama9.cracker;

import cz.cvut.fit.cernama9.cracker.attacks.NearPrimes;
import cz.cvut.fit.cernama9.cracker.attacks.PollardPMinus1;
import cz.cvut.fit.cernama9.cracker.attacks.RSAAttack;
import cz.cvut.fit.cernama9.cracker.attacks.Wiener;
import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;
import cz.cvut.fit.cernama9.cracker.utilities.SimpleRSAPublicKey;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.sql.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public class CertificateTester
{
	/**
	 * Prints the correct usage of this program
	 */
	private static void printCorrectUsage(Options options) {
		HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.printHelp("java -jar CertificateTester.jar", options, true);
	}

	private static void setRecordAsProcessed(Connection connection, String id_certificate) throws SQLException
	{
		final PreparedStatement preparedStatement = connection.prepareStatement("UPDATE certificate SET processed = 1 WHERE id_certificate = ?");
		preparedStatement.setString(1, id_certificate);
		preparedStatement.closeOnCompletion();
		preparedStatement.execute();
	}

	private static void saveAttackResult(Connection connection,
	                                     AttackResult result,
	                                     String attackName,
	                                     String id_certificate) throws SQLException
	{
		PreparedStatement outputData = connection.prepareStatement("INSERT INTO attack (id_certificate, attack, private_exponent, prime_p, prime_q) VALUES (?,?,?,?,?)");
		outputData.closeOnCompletion();
		outputData.setString(1, id_certificate);
		outputData.setString(2, attackName);

		if (result.getD() != null)
		{
			outputData.setString(3, result.getD().toString());
		}
		else
		{
			outputData.setNull(3, Types.VARCHAR);
		}

		if (result.getP() != null)
		{
			outputData.setString(4, result.getP().toString());
		}
		else
		{
			outputData.setNull(4, Types.VARCHAR);
		}

		if (result.getQ() != null)
		{
			outputData.setString(5, result.getQ().toString());
		}
		else
		{
			outputData.setNull(5, Types.VARCHAR);
		}

		outputData.execute();
	}

	public static void main(String[] args)
	{
		Options options = new Options();
		options.addOption(Option.builder("data")
				.hasArg()
				.required()
				.desc("data file location (SQLite database) - the output file of CertificateDownloader.")
				.argName("file")
				.build());


		final CommandLineParser parser = new DefaultParser();
		final CommandLine cmd;

		try {
			cmd = parser.parse(options, args);
		} catch (ParseException e) {
			System.err.println(e.getMessage());
			printCorrectUsage(options);
			System.exit(1);
			return;
		}

		final Connection sqlite;

		try
		{
			sqlite = setupDatabase(cmd.getOptionValue("data"));
		}
		catch (ClassNotFoundException ignored)
		{
			System.err.println("Unable to locate SQLite library");
			System.exit(1);
			return;
		}
		catch (FileNotFoundException ex)
		{
			System.err.println(ex.getMessage());
			System.exit(1);
			return;
		}
		catch (SQLException ex)
		{
			System.err.println("Unable to setup the database, SQL error: " + ex.getMessage());
			System.exit(1);
			return;
		}

		System.out.println("Database init completed. Starting parameter quality testing");

		try
		{
			final Statement inputData = sqlite.createStatement();

			final ResultSet resultSet = inputData.executeQuery("SELECT c.id_certificate, c.modulus, c.public_exponent FROM certificate c WHERE c.processed = 0 AND c.modulus_bits IS NOT NULL");

			final RSAAttack[] attacks = new RSAAttack[]{new Wiener(),
			                                            new NearPrimes(),
			                                            new PollardPMinus1()};

			while (resultSet.next())
			{
				final ExecutorService executorService = Executors.newFixedThreadPool(attacks.length); // number of threads

				final String id_certificate = resultSet.getString("id_certificate");
				final BigInteger n = new BigInteger(resultSet.getString("modulus")),
						e = new BigInteger(resultSet.getString("public_exponent"));

				final SimpleRSAPublicKey publicKey;

				//System.out.print(id_certificate + ": ");

				try
				{
					publicKey = new SimpleRSAPublicKey(n, e);
				}
				catch (IllegalArgumentException ex)
				{
					System.err.println("Invalid public key found (certificate thumbprint: \"" + id_certificate + "\". Skipping");
					continue;
				}

				for (RSAAttack attack : attacks)
				{
					executorService.submit(() -> {
						attack.run(publicKey);
						if (attack.getResult() != null)
						{
							try
							{
								saveAttackResult(sqlite, attack.getResult(), attack.getClass().getName(), id_certificate);
							}
							catch (SQLException ignored) {}
						}
					});
				}

				executorService.awaitTermination(3, TimeUnit.MINUTES);
				executorService.shutdownNow();

				System.out.println();

				setRecordAsProcessed(sqlite, resultSet.getString("id_certificate"));
			}

			System.out.println("All of the certificates were successfully processed. You may now review the database for details.");

		}
		catch (SQLException e)
		{
			System.err.println("Unable to retrieve certificate and scan data. Please verify the database file");
			try
			{
				sqlite.close();
			}
			catch (SQLException ignored) { }
			System.exit(1);
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
	}

	private static Connection setupDatabase(String filename)
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