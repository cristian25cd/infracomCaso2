package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.*;
import org.bouncycastle.asn1.x509.*;

/**
 *  
 */
public class Cliente
{
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

	public static final int PUERTO = 443;
	public static final String SERVIDOR = "infracomp.virtual.uniandes.edu.co";

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

	//-----------------------------------------------------------------
	// Atributos
	//-----------------------------------------------------------------
	private Socket socket;
	private BufferedReader lector;
	private PrintWriter escritor;
	private static OutputStream output;
	private static InputStream input;
	private static KeyPair keyPair;
	private static byte[] certServ;
	private static byte[] certClie;
	private static PublicKey pubKey;
	private static PrivateKey privKey;
	private static X509Certificate certificadoServidor;
	//-----------------------------------------------------------------
	// Constructor
	//-----------------------------------------------------------------
	public Cliente( )
	{
		try {
			socket = new Socket(SERVIDOR,PUERTO);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
			escritor = new PrintWriter(socket.getOutputStream(), true);
			
			//INPUT STREAM PARA RECIBIR FLUJO DE BYTES DEL SERVIDOR
			 input = socket.getInputStream();

			//OUTPUT STREAM PARA MANDAR FLUJO DE BYTES DEL SERVIDOR
			 output = socket.getOutputStream();

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
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());	

		Cliente c = new Cliente();
		String datos = "caso 2 infracom.";
		String respuesta="";

		try {
			//Etapa 1:

			c.escritor.println(HOLA);
			System.out.println("Se envio "+HOLA);

			String res =c.lector.readLine();
			System.out.println("se recibio "+res); //ACK

			String cadena =ALGORITMOS+":"+AES+":"+RSA+":"+HMACSHA256;
			c.escritor.println(cadena);
			System.out.println("Se envio "+cadena);
			System.out.println("se recibio "+c.lector.readLine());//STATUS

			//Etapa 2:

			//LECTURA DEL CERTIDFICADO SERVIDOR

			System.out.println("se recibio " + c.lector.readLine());//CERTSRV
			
			byte[] certificadoServidorBytes = new byte[529];
			int numBytesLeidos = input.read(certificadoServidorBytes);
			CertificateFactory creador = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
			X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(in);
			
			System.out.println(certificadoServidor.getPublicKey());
			//Etapa 3:

			//CREACION Y ENVIO DEL CERTIFICADO CLIENTE
			c.escritor.println(CERTCLNT);
			System.out.println("Se envio "+CERTCLNT);

			X509Certificate cer = certificado();
			certClie = cer.getEncoded();
		
			output.write(certClie);
			output.flush();
			
			System.out.println("Se envio "+cer.getPublicKey());


			//Etapa 4:
			res=c.lector.readLine();
			byte[] llaveCifrada = Transformacion.destransformar(res.split(":")[1]);
			
			//Descifrar con llave privada la llave siemtrica
			
			
			//Cifrar con la llave publica del servidor la llave simetrica
			
			//Si estatus = a ok, enviar datos con la llave simetrica
			
			//luego enviar el hash de datos cifrados con la llave privada del cliente
			
			//Recibir la respuesta cifrada con la llave simetrica
			
			c.escritor.println();
			
			System.out.println("Se envio "+INIT);

			res=c.lector.readLine();
			System.out.println("se recibio "+res);

			if (res.contains(ERROR)) 
			{
				System.out.println("Error en la etapa 4.");
			}
			else
			{
				c.escritor.println(INFO+":"+datos);
				c.escritor.println(INFO+":"+datos);
				System.out.println("Se envio "+INFO);
				respuesta=c.lector.readLine();
				System.out.println("Se recibio "+respuesta);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
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
			keyGen = KeyPairGenerator.getInstance(RSA);
			keyGen.initialize(1024);
			keyPair = keyGen.generateKeyPair();
			privKey = keyPair.getPrivate();
			pubKey = keyPair.getPublic();	
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	public byte[] cifrar() {
		try {
			Cipher cipher = Cipher.getInstance(RSA);

			BufferedReader stdIn =new BufferedReader(new InputStreamReader(System.in));
			String pwd = stdIn.readLine();
			byte [] clearText = pwd.getBytes();
			String s1 = new String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			long startTime = System.nanoTime();
			byte [] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("clave cifrada: " + cipheredText);
			System.out.println("Tiempo asimetrico: " +
					(endTime - startTime));
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public void descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(RSA);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte [] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			System.out.println("clave original: " + s3);
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
		}
	}
}