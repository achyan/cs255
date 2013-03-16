/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;

class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    private String m_pwdFile;
    
    public MITMAdminServer( String localHost, int adminPort, String pwdFile, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
    	MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
				
		m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
		m_engine = engine;
		m_pwdFile = pwdFile;
    }

    public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while( true ) {
		    try {
			m_socket = m_serverSocket.accept();
	
			byte[] buffer = new byte[40960];
	
			Pattern userPwdPattern =
			    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
			
			BufferedInputStream in =
			    new BufferedInputStream(m_socket.getInputStream(),
						    buffer.length);
	
			// Read a buffer full.
			int bytesRead = in.read(buffer);
	
			String line =
			    bytesRead > 0 ?
			    new String(buffer, 0, bytesRead) : "";
	
			Matcher userPwdMatcher =
			    userPwdPattern.matcher(line);
	
			// parse username and pwd
			if (userPwdMatcher.find()) {
			    String password = userPwdMatcher.group(1);
	
			    // TODO(cs255): authenticate the user
	
			    boolean authenticated = true;
			    String saltedHash = readSaltedHash();
			    System.out.println("stored hash = " + saltedHash);			    
			    authenticated = BCrypt.checkpw(password, saltedHash);

			    // if authenticated, do the command
			    if( authenticated ) {
			    	System.out.println("authentication OK!");
			    	String command = userPwdMatcher.group(2);
//			    	String commonName = userPwdMatcher.group(3);
	
					doCommand(command);
			    } else {
			    	System.out.println("authentication failed. Bye!");
			    }
			}	
		    }
		    catch( InterruptedIOException e ) {
		    }
		    catch( Exception e ) {
			e.printStackTrace();
		    }
		}
    }

    private String readSaltedHash() throws IOException {
    	FileInputStream fis = null;
        BufferedReader reader = null;
        String result = "";
        try {
            fis = new FileInputStream(m_pwdFile);
            reader = new BufferedReader(new InputStreamReader(fis));
          
            result = reader.readLine();            
          
        } catch (IOException ex) {
            ex.printStackTrace();        
        } finally {
            try {
                reader.close();
                fis.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
		return result;
    }
    
    private void sendString(final String str) throws IOException {
		PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
		writer.println(str);
		writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {

		// TODO(cs255): instead of greeting admin client, run the indicated command
    	if(cmd.equals("shutdown")) {
    		// shut down the whole process
    		System.exit(0);
    	} else if(cmd.equals("stats")) {    		
    		sendString("stats: total requests = " + m_engine.getNumRequests());
    	} else {
    		sendString("Unknown command. Bye!");
    	}
//		sendString("How are you Admin Client !!");	
		m_socket.close();
    }

}
