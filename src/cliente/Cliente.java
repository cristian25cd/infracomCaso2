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
    // Constantes
    //-----------------------------------------------------------------



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
    
}