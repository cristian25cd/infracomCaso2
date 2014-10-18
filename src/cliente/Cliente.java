package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

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
	private final static String HMACSHA1 = "AES";
	private final static String HMACSHA256 = "HMACSHA256";
	
	public Cliente( )
    {
    	try {
			socket = new Socket("infracomp.virtual.uniandes.edu.co",80);
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
			boolean termino =false;
			while (!termino) 
			{
				String res =c.lector.readLine();

				if (res.equals(ACK)) 
				{
					c.escritor.println(ALGORITMOS+":"+DES+":"+BLOWFISH+":"+HMACSHA1);
					res =c.lector.readLine();
					if (res.contains(ERROR)) 
					{
						System.out.println("Error en la etapa 1.");
						termino=true;
					}
				}
				else if (res.equals(CERTSRV)) 
				{
					res=c.lector.readLine();
					certServ = Transformacion.destransformar(res);
				}
				else if (res.equals(CERTCLNT)) 
				{
					X509Certificate cert = certificado(); 
					certClie= cert.getEncoded();
					c.escritor.println(Transformacion.transformar(certClie));
				}
				else if (res.equals(INIT)) 
				{
					c.escritor.println(INIT);
					res=c.lector.readLine();
					if (res.contains(ERROR)) 
					{
						System.out.println("Error en la etapa 4.");
						termino=true;
					}
					else
					{
						c.escritor.println(INFO+":"+datos);
						c.escritor.println(INFO+":"+datos);
						respuesta=c.lector.readLine();
						termino=true;
					}
				}
				else
				{
					termino=true;
				}
				
			}
//			if (res!=ACK) 
//			{
//				System.out.println("Error, se esperaba "+ ACK+ " pero se recibio "+res);
//			}
//			else
//			{
//				c.escritor.println(ALGORITMOS+":"+DES+":"+BLOWFISH+":"+HMACSHA1);
//				res=c.lector.readLine();
//				if (res.equals(ERROR)) 
//				{
//					System.out.println("Hubo error en la etapa 1.");
//				}
//				else
//				{
//					res=c.lector.readLine();
//				}
//			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private static X509Certificate  certificado() {
		// TODO Auto-generated method stub
		return null;
	}    
}