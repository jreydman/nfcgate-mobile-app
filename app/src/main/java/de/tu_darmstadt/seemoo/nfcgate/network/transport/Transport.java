package de.tu_darmstadt.seemoo.nfcgate.network.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public abstract class Transport {
    protected final String mHostname;
    protected final int mPort;

    protected InetSocketAddress mAddress;

    protected Socket mSocket = null;
    // Whether transport connect was called at some point. This prevents double connection attempts.
    protected boolean connectCalled = false;

    /**
     * Creates a Transport to the given hostname and port. Does not connect automatically.
     *
     * @param hostname Hostname or IP address.
     * @param port Port..
     */
    public Transport(String hostname, int port) {
        mHostname = hostname;
        mPort = port;
    }

    /**
     * Connects the transport if not already connected. Returns whether connection status changed.
     *
     * @return True if new connection was established, false if status did not change.
     * @throws IOException Any socket exception.
     */
    public boolean connect() throws IOException {
        if (mSocket != null || connectCalled)
            return false;

        mAddress = new InetSocketAddress(mHostname, mPort);
        connectCalled = true;
        mSocket = createSocket();
        connectSocket();
        return true;
    }

    /**
     * Closes the Transport by closing the socket.
     *
     * @param allowReconnects If this Transport instance should be allowed to reconnect.
     */
    public void close(boolean allowReconnects) {
        if (mSocket != null) {
            try {
                mSocket.close();
            } catch (IOException e) {
                /* ignored */
            }
        }
        mSocket = null;

        if (allowReconnects)
            connectCalled = false;
    }

    public Socket socket() {
        return mSocket;
    }

    protected abstract Socket createSocket() throws IOException;

    protected abstract void connectSocket() throws IOException;
}
