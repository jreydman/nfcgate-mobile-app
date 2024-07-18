package de.tu_darmstadt.seemoo.nfcgate.network.transport;

import java.io.IOException;
import java.net.Socket;

public class PlainTransport extends Transport {
    public PlainTransport(String hostname, int port) {
        super(hostname, port);
    }

    @Override
    protected Socket createSocket() {
        return new Socket();
    }

    @Override
    protected void connectSocket() throws IOException {
        mSocket.connect(mAddress, 10000);
    }
}
