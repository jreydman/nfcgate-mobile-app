package de.tu_darmstadt.seemoo.nfcgate.network;

import static org.junit.Assert.*;

import android.content.Context;
import android.util.Log;

import androidx.preference.PreferenceManager;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

import de.tu_darmstadt.seemoo.nfcgate.network.data.NetworkStatus;
import de.tu_darmstadt.seemoo.nfcgate.network.transport.PlainTransport;
import de.tu_darmstadt.seemoo.nfcgate.network.transport.TLSTransport;

public class ServerConnectionTest {
    @Rule
    public Timeout connectionTimeout = Timeout.seconds(10);

    public static class Callback implements ServerConnection.Callback {
        protected boolean mCalled = false;

        private final NetworkStatus expected;

        public Callback(NetworkStatus expected) {
            this.expected = expected;
        }

        @Override
        public void onReceive(byte[] data) {

        }

        @Override
        public void onNetworkStatus(NetworkStatus status) {
            synchronized (this) {
                // ignore generic ERROR here
                if (status.equals(NetworkStatus.ERROR))
                    return;

                Log.d("ServerConnectionTest", "Got status " + status.name());

                if (mCalled)
                    fail("Callback called multiple times");
                mCalled = true;
                if (!expected.equals(status))
                    fail("Connection check failed. expected: " + expected + "; actual: " + status.name());
            }
        }

        public synchronized boolean called() {
            return mCalled;
        }
    }

    @Before
    public void setUp() throws Exception {
        // clear preferences
        PreferenceManager.getDefaultSharedPreferences(InstrumentationRegistry.getInstrumentation().getContext())
                .edit().clear().commit();
        InstrumentationRegistry.getInstrumentation().getContext().getSharedPreferences("certificate_trust", Context.MODE_PRIVATE)
                .edit().clear().commit();
        // init clean UserTrustManager
        UserTrustManager.init(InstrumentationRegistry.getInstrumentation().getContext());
    }

    @After
    public void tearDown() throws Exception {
    }

    protected void busyWaitFor(Callback callback) throws InterruptedException {
        while (!callback.called()) {
            Thread.sleep(100);
        }
        // ensure callback is called exactly once
        Thread.sleep(1000);
    }

    protected void testTLS(String host, Callback callback) throws InterruptedException {
        ServerConnection conn = new ServerConnection(new TLSTransport(host, 443));
        conn.setCallback(callback);

        conn.connect();
        busyWaitFor(callback);
        conn.disconnect();
    }

    @Test
    public void testConnectPlainSuccess() throws InterruptedException {
        {
            ServerConnection conn = new ServerConnection("badssl.com", 443, true);
            Callback callback = new Callback(NetworkStatus.CONNECTED);
            conn.setCallback(callback);

            conn.connect();
            busyWaitFor(callback);
            conn.disconnect();
        }
        {
            ServerConnection conn = new ServerConnection(new PlainTransport("badssl.com", 443));
            Callback callback = new Callback(NetworkStatus.CONNECTED);
            conn.setCallback(callback);

            conn.connect();
            busyWaitFor(callback);
            conn.disconnect();
        }
    }

    @Test
    public void testConnectTLSSuccess() throws InterruptedException {
        testTLS("badssl.com", new Callback(NetworkStatus.CONNECTED));
    }

    @Test
    public void testConnectTLSExpired() throws InterruptedException {
        testTLS("expired.badssl.com", new Callback(NetworkStatus.ERROR_TLS));
    }

    @Test
    public void testConnectTLSWrongHost() throws InterruptedException {
        testTLS("wrong.host.badssl.com", new Callback(NetworkStatus.ERROR_TLS));
    }

    @Test
    public void testConnectTLSRevoked() throws InterruptedException {
        testTLS("revoked.badssl.com", new Callback(NetworkStatus.ERROR_TLS));
    }

    @Test
    public void testConnectTLSUnknownTrust() throws InterruptedException {
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNKNOWN));
    }

    @Test
    public void testConnectTLSTrustManagerTrusted() throws InterruptedException {
        // self-signed trust is unknown
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNKNOWN));

        // set self-signed trusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.TRUSTED);

        // self-signed trust is now trusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.CONNECTED));
    }

    @Test
    public void testConnectTLSTrustManagerUntrusted() throws InterruptedException {
        // self-signed trust is unknown
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNKNOWN));

        // set self-signed untrusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.UNTRUSTED);

        // self-signed trust is now untrusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNTRUSTED));
    }

    @Test
    public void testConnectTLSTrustManagerTrustedUntrusted() throws InterruptedException {
        // self-signed trust is unknown
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNKNOWN));

        // set self-signed trusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.TRUSTED);

        // self-signed trust is now trusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.CONNECTED));

        // set self-signed untrusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.UNTRUSTED);

        // self-signed trust is now untrusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNTRUSTED));
    }
    @Test
    public void testConnectTLSTrustManagerUntrustedTrusted() throws InterruptedException {
        // self-signed trust is unknown
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNKNOWN));

        // set self-signed untrusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.UNTRUSTED);

        // self-signed trust is now untrusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.ERROR_TLS_CERT_UNTRUSTED));

        // set self-signed trusted
        UserTrustManager.getInstance().setCertificateTrust(UserTrustManager.getInstance().getCachedCertificateChain(), UserTrustManager.Trust.TRUSTED);

        // self-signed trust is now trusted
        testTLS("self-signed.badssl.com", new Callback(NetworkStatus.CONNECTED));

    }
}