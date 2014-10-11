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
    // Constructores
    //-----------------------------------------------------------------

    /**
     *  
     */
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
    
    
    //-----------------------------------------------------------------
    // Puntos de Extensión
    //-----------------------------------------------------------------

    /**
     * Método para la extensión 1
     * @return respuesta1
     */
    public String metodo1(String mensaje)
    {
    	escritor.println(mensaje);
        return "Se envió el mensaje";
    }

    /**
     * Método para la extensión2
     * @return respuesta2
     */
    public String metodo2( )
    {
        return "Respuesta 2";
    }


}