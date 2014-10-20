package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PrincipalUtil;
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
			socket = new Socket("infracomp.virtual.uniandes.edu.co",443);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
			escritor = new PrintWriter(socket.getOutputStream(), true);
			getKey();
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
					String cadena =ALGORITMOS+":"+AES+":"+RSA+":"+HMACSHA256;
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
					try {
						res = c.lector.readLine();
						System.out.println("se recibio " + res);
						
						//LECTURA DEL CERTIDFICADO
						certServ= res.getBytes();
						
						//CREACION Y ENVIO DEL CERTIFICADO
						c.escritor.println(CERTCLNT);
						System.out.println("Se envio "+CERTCLNT);
						
						X509Certificate cer = certificado();
						certClie = cer.getEncoded();
						c.escritor.println(certClie);
						System.out.println("Se envio "+certClie);
						
					} catch (Exception e) {
						// TODO: handle exception
					}
				
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
		}

	}

	private static X509Certificate  certificado() throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pubKey);
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
				KeyPurposeId.id_kp_serverAuth));
		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));
		return certGen.generateX509Certificate(privKey, "BC");

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