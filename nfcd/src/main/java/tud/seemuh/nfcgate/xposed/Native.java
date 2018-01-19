package tud.seemuh.nfcgate.xposed;


public class Native {
    static {
        Instance = new Native();
    }
    public static final Native Instance;
    public native void setEnabled(boolean enabled);
    public native boolean isEnabled();
    public native void uploadConfiguration(byte bitf, byte plat, byte sak, byte[] hist, byte[] uid);
    public native void enablePolling();
    public native void disablePolling();
}
