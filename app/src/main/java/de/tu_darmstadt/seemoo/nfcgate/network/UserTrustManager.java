package de.tu_darmstadt.seemoo.nfcgate.network;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

public class UserTrustManager {
    public enum Trust {
        TRUSTED,
        UNTRUSTED,
        UNKNOWN;

        public static Trust from(int value) {
            if (value >= Trust.UNKNOWN.ordinal())
                return Trust.UNKNOWN;
            return Trust.values()[value];
        }

    }
    public static class UnknownTrustException extends RuntimeException {}
    public static class UntrustedException extends RuntimeException {}

    private static final String TAG = "UserTrustManager";

    // singleton
    private static UserTrustManager mInstance;
    public static UserTrustManager getInstance() {
        return mInstance;
    }
    public static void init(Context context) {
        mInstance = new UserTrustManager(context);
    }

    protected SharedPreferences mPreferences;
    protected X509Certificate[] cachedCertificateChain = null;

    public static String certificateChainHash(X509Certificate[] chain) {
        try {
            return Base64.encodeToString(certificateChainFingerprint(chain, "SHA512"), Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "Cannot calculate certificate hash", e);
            return null;
        }
    }

    public static byte[] certificateChainFingerprint(X509Certificate[] certificateChain, String algorithm) {
        try {
            MessageDigest hash = MessageDigest.getInstance(algorithm);
            for (X509Certificate certificate : certificateChain)
                hash.update(certificate.getEncoded());
            return hash.digest();
        } catch (Exception e) {
            Log.e(TAG, "Cannot calculate certificate hash", e);
            return new byte[]{};
        }
    }

    private UserTrustManager(Context context) {
        // use a dedicated certificate trust preferences file to avoid cluttering application
        // settings and allow easy clearing
        mPreferences = context.getSharedPreferences("certificate_trust", Context.MODE_PRIVATE);
    }

    public Trust checkCertificate(X509Certificate[] chain) {
        // get user trust value for certificate chain, defaulting to UNKNOWN trust
        int trustValue = mPreferences.getInt(certificateChainHash(chain), Trust.UNKNOWN.ordinal());
        return Trust.from(trustValue);
    }

    public void setCertificateTrust(X509Certificate[] chain, Trust trust) {
        mPreferences.edit().putInt(certificateChainHash(chain), trust.ordinal()).apply();
    }

    public void clearTrust() {
        // clears all saved certificate trust
        mPreferences.edit().clear().apply();
    }

    public X509Certificate[] getCachedCertificateChain() {
        return cachedCertificateChain;
    }

    public void setCachedCertificateChain(X509Certificate[] cachedCertificate) {
        this.cachedCertificateChain = cachedCertificate;
    }
}
