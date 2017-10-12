package de.rub.nds.bc;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 * Basic Bouncy Castle TLS server. Do not use for real applications, just a demo
 * server for security testing purposes.
 * 
 * Works for BC 1.50 and higher
 *
 * From:
 * https://stackoverflow.com/questions/18065170/how-do-i-do-tls-with-bouncycastle
 * and
 * https://www.programcreek.com/java-api-examples/index.php?source_dir=usc-master/usc-channel-impl/src/main/java/org/opendaylight/usc/crypto/dtls/DtlsUtils.java
 * and https://github.com/RUB-NDS/TLS-Attacker
 *
 */
public class BouncyCastleTLSServer extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(BouncyCastleTLSServer.class);

    private static final String PATH_TO_JKS = "rsa2048.jks";

    private static final String JKS_PASSWORD = "password";

    private static final String ALIAS = "1";

    private static final int PORT = 4433;

    private final int port;

    private final KeyPair keyPair;

    private final Certificate cert;

    private boolean shutdown;

    private final ServerSocket serverSocket;

    public BouncyCastleTLSServer(KeyStore keyStore, String password, String alias, int port) throws IOException, 
            KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.port = port;
        cert = loadTLSCertificate(keyStore, alias);
        serverSocket = new ServerSocket(port);
        keyPair = getKeyPair(keyStore, alias, password.toCharArray());
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.security.debug", "ssl");
        String path;
        String password;
        String alias;
        int port;

        switch (args.length) {
            case 4:
                path = args[0];
                password = args[1];
                alias = args[2];
                port = Integer.parseInt(args[3]);
                break;
            case 0:
                path = PATH_TO_JKS;
                password = JKS_PASSWORD;
                alias = ALIAS;
                port = PORT;
                break;
            default:
                System.out.println("Usage (run with): java -jar [name].jar [jks-path] "
                        + "[password] [alias] [port]");
                return;
        }

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(path), password.toCharArray());

        BouncyCastleTLSServer server = new BouncyCastleTLSServer(ks, password, alias, port);
        Thread t = new Thread(server);
        t.start();
    }

    @Override
    public void run() {
        while (!shutdown) {
            try {
                LOGGER.info("Listening on port " + port + "...\n");
                final Socket socket = serverSocket.accept();

                TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(
                        socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
                tlsServerProtocol.accept(new DefaultTlsServer() {
                    @Override
                    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
                        return new DefaultTlsSignerCredentials(context, cert, PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));
                    }
                });
                ConnectionHandler ch = new ConnectionHandler(socket);
                Thread t = new Thread(ch);
                t.start();
            } catch (IOException ex) {
                LOGGER.info(ex.getLocalizedMessage(), ex);
            }
        }

        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            LOGGER.info(ex.getLocalizedMessage(), ex);
        }
        LOGGER.info("Shutdown complete");
    }

    /**
     * Loads a certificate from a keystore
     *
     * @param keyStore
     * @param alias
     * @return
     * @throws KeyStoreException
     * @throws CertificateEncodingException
     * @throws IOException
     */
    public static org.bouncycastle.crypto.tls.Certificate loadTLSCertificate(KeyStore keyStore, String alias)
            throws KeyStoreException, CertificateEncodingException, IOException {
        java.security.cert.Certificate sunCert = keyStore.getCertificate(alias);
        byte[] certBytes = sunCert.getEncoded();

        ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

        org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
        certs[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs);
        return tlsCerts;
    }

    public static KeyPair getKeyPair(final KeyStore keystore, final String alias, char[] password) 
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

//    static Certificate loadCertificateChain(String[] resources) throws IOException {
//        org.bouncycastle.asn1.x509.Certificate[] chain = new org.bouncycastle.asn1.x509.Certificate[resources.length];
//        for (int i = 0; i < resources.length; ++i) {
//            chain[i] = loadCertificateResource(resources[i]);
//        }
//        return new Certificate(chain);
//    }
//
//    static org.bouncycastle.asn1.x509.Certificate loadCertificateResource(String resource) throws IOException {
//        PemObject pem = loadPemResource(resource);
//        if (pem.getType().endsWith("CERTIFICATE")) {
//            return org.bouncycastle.asn1.x509.Certificate.getInstance(pem.getContent());
//        }
//        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
//    }
//
//    static PemObject loadPemResource(String resource) throws IOException {
//        // InputStream s = TlsTestUtils.class.getResourceAsStream(resource); 
//        InputStream s = new FileInputStream(resource);
//        PemReader p = new PemReader(new InputStreamReader(s));
//        PemObject o = p.readPemObject();
//        p.close();
//        return o;
//    }
//
}
