package cz.cvut.fit.cernama9.cracker.attacks;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 10.2.16.
 */
public interface RSAAttack
{
	void begin(RSAPublicKey certificate);

	void stop();
}
