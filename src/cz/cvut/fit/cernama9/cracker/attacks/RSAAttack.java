package cz.cvut.fit.cernama9.cracker.attacks;

import cz.cvut.fit.cernama9.cracker.utilities.AttackResult;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public interface RSAAttack
{
	/**
	 * Begin the attack on a RSA public key specified
	 * @param publicKey The target publicKey
	 */
	void run(RSAPublicKey publicKey);

	/**
	 * Begin the attack on a RSA public key specified
	 * @param publicKey The target publicKey
	 */
	void test(RSAPublicKey publicKey);

	/**
	 * Can be used for testing
	 * @return The result of the (successful) attack
	 */
	AttackResult getResult();
}
