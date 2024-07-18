package de.tu_darmstadt.seemoo.nfcgate;

import android.app.Application;
import android.content.Context;

public class NFCGateApplication extends Application {

    private static Context context;

    public void onCreate() {
        super.onCreate();
        NFCGateApplication.context = getApplicationContext();
    }

    public static Context getAppContext() {
        return NFCGateApplication.context;
    }
}