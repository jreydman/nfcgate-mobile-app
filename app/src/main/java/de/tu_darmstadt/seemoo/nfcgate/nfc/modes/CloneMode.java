package de.tu_darmstadt.seemoo.nfcgate.nfc.modes;

import de.tu_darmstadt.seemoo.nfcgate.network.data.NetworkStatus;
import de.tu_darmstadt.seemoo.nfcgate.util.NfcComm;

public class CloneMode extends BaseMode {
    @Override
    public void onEnable() {
        // reset polling and config
        mManager.resetConfig();
    }

    @Override
    public void onDisable() {
        // reset polling and config after mode ends
        mManager.resetConfig();
    }

    @Override
    public void onData(boolean isForeign, NfcComm data) {
        // clone tag, also disables polling
        mManager.applyData(data);
    }

    @Override
    public void onNetworkStatus(NetworkStatus status) {
        // no-op: clone mode has no network activity
    }
}
