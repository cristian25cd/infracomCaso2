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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
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
	//private final static String BLOWFISH = "Blowfish";
	//private final static String RC4 ="RC4";

	private final static String RSA = "RSA";

	//private final static String HMACMD5 ="HMACMD5";
	//private final static String HMACSHA1 = "HMACSHA1";
	private final static String HMACSHA256 = "HMACSHA256";

	//-----------------------------------------------------------------
	// Atributos
	//-----------------------------------------------------------------

	private Socket socket;
	private BufferedReader lector;
	private PrintWriter escritor;
	private OutputStream output;
	private InputStream input;
	private KeyPair keyPair;
	private byte[] certServ;
	private byte[] certClie;
	private PublicKey pubKey;
	private PrivateKey privKey;
	private X509Certificate certificadoServidor;
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

			String datos = "caso 2 infracom.";
			String respuesta="";

			//Etapa 1:

			escritor.println(HOLA);
			System.out.println("Se envio "+HOLA);

			String res =lector.readLine();
			System.out.println("se recibio "+res); //ACK

			String cadena =ALGORITMOS+":"+AES+":"+RSA+":"+HMACSHA256;
			escritor.println(cadena);
			System.out.println("Se envio "+cadena);
			
			System.out.println("se recibio "+lector.readLine());//STATUS

			//Etapa 2:

			//LECTURA DEL CERTIFICADO SERVIDOR

			System.out.println("se recibio " + lector.readLine());//CERTSRV

			byte[] certificadoServidorBytes = new byte[520];
		
			int av= input.available();
			
			if (av<520) 
			{
				System.out.println(av);
			}
			int numBytesLeidos=input.read(certificadoServidorBytes);
		
			System.out.println("Numero de bytes leidos "+numBytesLeidos);
			
			CertificateFactory creador = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
			X509Certificate certificadoServidor = (X509Certificate)creador.generateCertificate(in);

			System.out.println(certificadoServidor.getPublicKey());
			//Etapa 3:

			//CREACION Y ENVIO DEL CERTIFICADO CLIENTE
			escritor.println(CERTCLNT);
			System.out.println("Se envio "+CERTCLNT);

			java.security.cert.X509Certificate cer = certificado();
			certClie = cer.getEncoded();

			output.write(certClie);
			output.flush();

			System.out.println("Se envio "+cer.getPublicKey());


			//Etapa 4:
			res=lector.readLine();
			byte[] llaveCifrada = Transformacion.destransformar(res.split(":")[1]);

			//Descifrar con llave privada la llave siemtrica

			String llaveSimetrica=descifrar(llaveCifrada);

			//Cifrar con la llave publica del servidor la llave simetrica
			byte[] cifrado = cifrar(llaveSimetrica, certificadoServidor.getPublicKey());
			escritor.println(Transformacion.transformar(cifrado));

			//Si estatus = a ok, enviar datos con la llave simetrica
			lector.readLine();

			SecretKeySpec key = new SecretKeySpec(llaveSimetrica.getBytes(), "AES");   
			Cipher cipher;   

			cipher = Cipher.getInstance("AES");

			//Comienzo a encriptar    
			cipher.init(Cipher.ENCRYPT_MODE, key);    
			byte[] campoCifrado = cipher.doFinal(datos.getBytes());
			escritor.println(Transformacion.transformar(campoCifrado));


			//luego enviar el hash de datos cifrados con la llave privada del cliente

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			md.update(datos.getBytes("UTF-8"));
			byte[] digest = md.digest();

			escritor.println(Transformacion.transformar(cifrar(digest, keyPair.getPrivate())));

			//Recibir la respuesta cifrada con la llave simetrica

			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] datosDecifrados = cipher.doFinal(Transformacion.destransformar(lector.readLine()));    
			String mensaje_original = new String(datosDecifrados);     
			System.out.println(mensaje_original); 

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}

	private X509Certificate  certificado() throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException {

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

	private void getKey() 
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

	private byte[] cifrar(String pwd, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance(RSA);
			byte [] clearText = pwd.getBytes();
			String s1 = new String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, key);
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

	private byte[] cifrar(byte[] clearText, PrivateKey key) {
		try {
			Cipher cipher = Cipher.getInstance(RSA);
			String s1 = new String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, key);
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

	private String descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(RSA);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte [] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			System.out.println("clave original: " + s3);
			return s3;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
		}
		return null;
	}

	//-----------------------------------------------------------------
	// Métodos
	//-----------------------------------------------------------------
	
	
	//-----------------------------------------------------------------
	// Main
	//-----------------------------------------------------------------
	
	public static void main(String[] args) 
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());	
	
		Cliente c = new Cliente();
	
	}
}