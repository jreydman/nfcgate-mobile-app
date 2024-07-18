package de.tu_darmstadt.seemoo.nfcgate.util;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class CertUtils {
    public static String getPublicKeyDescription(PublicKey key) {
        StringBuilder sb = new StringBuilder(key.getAlgorithm());
        sb.append(" (");

        switch (key.getAlgorithm()) {
            case "EC":
                getECPublicKeyDescription((ECPublicKey) key, sb);
                break;
            case "RSA":
                getRSAPublicKeyDescription((RSAPublicKey) key, sb);
                break;
            default:
                sb.append("unknown key type");
        }
        return sb.append(")").toString();
    }

    private static void getECPublicKeyDescription(ECPublicKey key, StringBuilder sb) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(key.getParams());

            String curveName = params.getParameterSpec(ECGenParameterSpec.class).getName();
            int curveSize = key.getParams().getCurve().getField().getFieldSize();

            sb.append("curve ").append(curveName)
                    .append(" - ")
                    .append(curveSize).append(" bits");
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ignored) { }
    }

    private static void getRSAPublicKeyDescription(RSAPublicKey key, StringBuilder sb) {
        sb.append(key.getModulus().bitLength()).append(" bits");
    }
}
