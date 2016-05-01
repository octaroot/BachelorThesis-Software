package cz.cvut.fit.cernama9.scanner;

import java.security.cert.X509Certificate;

/**
 * @author Martin Černáč (cernama9@fit.cvut.cz)
 * @since 19.4.16.
 */
class CertificateResponse
{
	private X509Certificate certificate;
	private Exception       exception;

	CertificateResponse(X509Certificate certificate)
	{
		this.certificate = certificate;
		this.exception = null;
	}

	CertificateResponse(X509Certificate certificate, Exception exception)
	{
		this.certificate = certificate;
		this.exception = exception;
	}

	CertificateResponse(Exception exception)
	{
		this.exception = exception;
		this.certificate = null;
	}

	X509Certificate getCertificate()
	{
		return certificate;
	}

	Exception getException()
	{
		return exception;
	}
}
