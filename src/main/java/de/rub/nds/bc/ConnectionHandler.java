package de.rub.nds.bc;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.tls.TlsServerProtocol;

public class ConnectionHandler implements Runnable {

    private final static Logger LOGGER = LogManager.getLogger();

    private final TlsServerProtocol tlsServerProtocol;

    public ConnectionHandler(TlsServerProtocol tlsServerProtocol) {
	this.tlsServerProtocol = tlsServerProtocol;
    }

    @Override
    public void run() {
	LOGGER.debug("new Thread started");

	try {
	    final BufferedReader br = new BufferedReader(new InputStreamReader(tlsServerProtocol.getInputStream()));
	    final BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(tlsServerProtocol.getOutputStream()));
	    String line = "";
            
	    while ((line = br.readLine()) != null) {
		LOGGER.debug(line);
		bw.write("ack");
		bw.flush();
	    }
	} catch (IOException ex) {
	    LOGGER.debug(ex.getLocalizedMessage(), ex);
	} finally {
	    try {
	    tlsServerProtocol.close();
	    } catch (final IOException ex) {
		LOGGER.debug(ex.getLocalizedMessage(), ex);
	    }
	}
    }
}