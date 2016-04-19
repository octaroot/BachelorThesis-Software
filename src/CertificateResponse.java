import java.security.cert.X509Certificate;

/**
 * @author martin (cernama9@fit.cvut.cz)
 * @since 19.4.16.
 */
public class CertificateResponse
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

	public X509Certificate getCertificate()
	{
		return certificate;
	}

	public Exception getException()
	{
		return exception;
	}
}
