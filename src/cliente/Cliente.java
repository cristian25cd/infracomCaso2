package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

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

		try {
			c.escritor.println(HOLA);
			String res =c.lector.readLine();
			if (res!=ACK) 
			{
				System.out.println("Error, se esperaba "+ ACK+ " pero se recibio "+res);
			}
			else
			{
				c.escritor.println(ALGORITMOS+":"+DES+":"+BLOWFISH+":");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}    
}