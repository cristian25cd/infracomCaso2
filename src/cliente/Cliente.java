package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.util.*;

/**
 *  
 */
public class Cliente
{
	//-----------------------------------------------------------------
	// Atributos
	//-----------------------------------------------------------------
	private Socket socket;
	private BufferedReader lector;
	private PrintWriter escritor;
	private static byte[] certServ;
	private static byte[] certClie;
	private static PublicKey pubKey;
	private static PrivateKey privKey;

	//-----------------------------------------------------------------
	// Constantes
	//-----------------------------------------------------------------

	private final static String HOLA ="HOLA";
	private final static String ACK = "ACK";
	private final static String ALGORITMOS = "ALGORITMOS";
	private final static String STATUS ="STATUS";
	private final static String OK = "OK";
	private final static String ERROR = "ERROR";
	private final static String CERTSRV = "CERTSRV";
	private final static String CERTCLNT ="CERTCLNT";
	private final static String INIT = "INIT";
	private final static String INFO = "INFO"; 

	//-----------------------------------------------------------------
	// Constantes Algoritmos
	//-----------------------------------------------------------------

	private final static String DES ="DES";
	private final static String AES = "AES";
	private final static String BLOWFISH = "Blowfish";
	private final static String RC4 ="RC4";

	private final static String RSA = "RSA";

	private final static String HMACMD5 ="HMACMD5";
	private final static String HMACSHA1 = "HMACSHA1";
	private final static String HMACSHA256 = "HMACSHA256";

	public Cliente( )
	{
		try {
			socket = new Socket("infracomp.virtual.uniandes.edu.co",80);//443
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
			escritor = new PrintWriter(socket.getOutputStream(), true);
		} 
		catch (UnknownHostException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	//-----------------------------------------------------------------
	// Métodos
	//-----------------------------------------------------------------

	public static void main(String[] args) 
	{
		Cliente c = new Cliente();
		String datos = "caso 2 infracom.";
		String respuesta="";

		try {
			c.escritor.println(HOLA);
			System.out.println("Se envio "+HOLA);
			boolean termino =false;
			while (!termino) 
			{
				String res =c.lector.readLine();
				System.out.println("se recibio "+res);
				if (res.equals(ACK)) 
				{
					String cadena =ALGORITMOS+":"+RC4+":"+RSA+":"+HMACSHA1;
					c.escritor.println(cadena);
					System.out.println("Se envio "+cadena);

					res =c.lector.readLine();
					System.out.println("se recibio "+res);

					if (res.contains(ERROR)) 
					{
						System.out.println("Error en la etapa 1.");
						termino=true;
					}
				}
				else if (res.equals(CERTSRV)) 
				{
					res=c.lector.readLine();
					System.out.println("se recibio "+res);
					certServ = Transformacion.destransformar(res);
				}
				else if (res.equals(CERTCLNT)) 
				{
					X509Certificate cert = certificado(); 
					certClie= cert.getEncoded();
					c.escritor.println(Transformacion.transformar(certClie));
					System.out.println("Se envio certClient");

				}
				else if (res.equals(INIT)) 
				{
					c.escritor.println(INIT);
					System.out.println("Se envio "+INIT);

					res=c.lector.readLine();
					System.out.println("se recibio "+res);

					if (res.contains(ERROR)) 
					{
						System.out.println("Error en la etapa 4.");
						termino=true;
					}
					else
					{
						c.escritor.println(INFO+":"+datos);
						c.escritor.println(INFO+":"+datos);
						System.out.println("Se envio "+INFO);
						respuesta=c.lector.readLine();
						System.out.println("Se recibio "+respuesta);
						termino=true;
					}
				}
				else
				{
					termino=true;
				}

			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static X509Certificate  certificado() {

		getKey();
		Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, 100);
 
        X509Name x509Name = new X509Name("CN=" + "CristianHugo");

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new DERInteger(BigInteger.valueOf(System.currentTimeMillis())));
        certGen.setIssuer(PrincipalUtil.getSubjectX509Principal(caCert));
        certGen.setSubject(x509Name);
        DERObjectIdentifier sigOID = X509Util.getAlgorithmOID("SHA1WithRSAEncryption");
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID, new DERNull());
        certGen.setSignature(sigAlgId);
        certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
                new ByteArrayInputStream(pubKey.getEncoded())).readObject()));
        certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
        certGen.setEndDate(new Time(expiry.getTime()));
         TBSCertificateStructure tbsCert = certGen.generateTBSCertificate();
	}

	private static void getKey() 
	{
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keypair = keyGen.generateKeyPair();
			privKey = keypair.getPrivate();
			pubKey = keypair.getPublic();	
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}    
}