package de.tu_darmstadt.seemoo.nfcgate.gui.fragment;

import de.tu_darmstadt.seemoo.nfcgate.R;
import de.tu_darmstadt.seemoo.nfcgate.network.UserTrustManager;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class SettingsFragment extends PreferenceFragmentCompat {

    private ActivityResultLauncher<Intent> filePickerLauncher;

    private void showCertificateOptionsDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext());
        builder.setItems(new CharSequence[]{"Upload new", "Reset current"}, (dialog, which) -> {
                    switch (which) {
                        case 0:
                            openClientCertificateChooser();
                            break;
                        case 1:
                            clearClientCertificate();
                            break;
                    }
        });
        builder.create().show();
    }

    private void openClientCertificateChooser() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/x-pkcs12"); // P12 file type
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        try {
            filePickerLauncher.launch(Intent.createChooser(intent, "Select a p12 client certificate file"));
        } catch (Exception exception) {
            Toast.makeText(getContext(), "Please install a file manager.", Toast.LENGTH_SHORT).show();
        }
    }

    private void promptForClientCertificatePasskeyPasskey(Uri uri) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
        builder.setTitle("Enter Passkey");

        final EditText input = new EditText(getContext());
        builder.setView(input);

        builder.setPositiveButton("OK", (dialog, which) -> {
            String passkey = input.getText().toString();
            verifyClientCertificatePasskey(uri, passkey);
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());

        builder.show();
    }

    private void verifyClientCertificatePasskey(Uri uri, String passkey) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = getContext().getContentResolver().openInputStream(uri);
            keyStore.load(inputStream, passkey.toCharArray());

            String alias = "client_certificate"; // Replace with actual alias from your PKCS#12 file
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, passkey.toCharArray());

            if (privateKey != null) {
                saveClientCertificate(uri, passkey);
            } else {
                Toast.makeText(getContext(), "Invalid passkey for alias: " + alias, Toast.LENGTH_SHORT).show();
            }

        } catch (Exception e) {
            Toast.makeText(getContext(), "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            e.printStackTrace(); // Print stack trace for debugging
        }
    }

    private void saveClientCertificate(Uri uri, String passkey) {
        try {
            // Save PKCS#12 file
            InputStream inputStream = getContext().getContentResolver().openInputStream(uri);
            File outputFile = new File(getContext().getFilesDir(), "client_certificate.p12");
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }
            inputStream.close();
            outputStream.close();

            // Save passkey
            SharedPreferences sharedPreferences = getContext().getSharedPreferences("client_certificate_prefs", Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putString("client_certificate_passkey", passkey);
            editor.apply();

            Toast.makeText(getContext(), "Certificate and passkey saved successfully", Toast.LENGTH_SHORT).show();
            findPreference("client_verify_certificate").setSummary(getCurrentClientCertificateInfo());

        } catch (Exception e) {
            Toast.makeText(getContext(), "Error saving certificate: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            e.printStackTrace(); // Print stack trace for debugging
        }
    }

    private String getCurrentClientCertificateInfo() {
        try {
            SharedPreferences sharedPreferences = getContext().getSharedPreferences("client_certificate_prefs", Context.MODE_PRIVATE);
            String passkey = sharedPreferences.getString("client_certificate_passkey", "");
            File clientCert = new File(getContext().getFilesDir(), "client_certificate.p12");

            // Проверяем, существует ли файл сертификата
            if (!clientCert.exists()) {
                return "No client certificate found.";
            }

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = new FileInputStream(clientCert);
            keyStore.load(inputStream, passkey.toCharArray());

            // Получаем информацию о сертификате
            Enumeration<String> aliases = keyStore.aliases();
            if (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate != null) {
                    return "Certificate Info:\n" +
                            "Type: " + certificate.getType() + "\n" +
                            "Issuer: " + ((X509Certificate) certificate).getIssuerDN() + "\n" +
                            "Subject: " + ((X509Certificate) certificate).getSubjectDN();
                } else {
                    return "No certificate information found.";
                }
            } else {
                return "No aliases found in the keystore.";
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "Error retrieving certificate information.";
        }
    }


    private void clearClientCertificate() {
        File certificateFile = new File(getContext().getFilesDir(), "client_certificate.p12");
        if (certificateFile.exists()) {
            certificateFile.delete();
        }

        SharedPreferences sharedPreferences = getContext().getSharedPreferences("certificate_prefs", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.remove("certificate_passkey");
        editor.apply();

        Toast.makeText(getContext(), "Client certificate cleared", Toast.LENGTH_SHORT).show();
        findPreference("client_verify_certificate").setSummary(getCurrentClientCertificateInfo());
    }

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.preferences, rootKey);

        findPreference("reset_usertrust").setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                UserTrustManager.getInstance().clearTrust();
                Toast.makeText(getContext(), R.string.settings_adv_replay_toast, Toast.LENGTH_LONG).show();
                return true;
            }
        });

        Preference certificatePreference = findPreference("client_verify_certificate");
        certificatePreference.setSummary(getCurrentClientCertificateInfo());

        certificatePreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                showCertificateOptionsDialog();
                return true;
            }
        });

        // Initialize file picker launcher
        filePickerLauncher = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
            if (result.getResultCode() == getActivity().RESULT_OK && result.getData() != null) {
                Uri uri = result.getData().getData();
                promptForClientCertificatePasskeyPasskey(uri);
            }
        });
    }
}
