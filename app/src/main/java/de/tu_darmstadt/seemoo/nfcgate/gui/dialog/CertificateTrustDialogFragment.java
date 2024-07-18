package de.tu_darmstadt.seemoo.nfcgate.gui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.tabs.TabLayoutMediator;

import java.security.cert.X509Certificate;

import de.tu_darmstadt.seemoo.nfcgate.R;
import de.tu_darmstadt.seemoo.nfcgate.network.UserTrustManager;
import de.tu_darmstadt.seemoo.nfcgate.util.CertUtils;
import de.tu_darmstadt.seemoo.nfcgate.util.Utils;

public class CertificateTrustDialogFragment extends DialogFragment {
    CertificateListAdapter mAdapter;

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        AlertDialog.Builder builder = new AlertDialog.Builder(requireActivity());

        View view = requireActivity().getLayoutInflater().inflate(R.layout.dialog_certtrust, null);

        X509Certificate[] certificateChain = UserTrustManager.getInstance().getCachedCertificateChain();
        mAdapter = new CertificateListAdapter(this, certificateChain);
        ViewPager2 viewPager = view.findViewById(R.id.pager);
        viewPager.setAdapter(mAdapter);

        new TabLayoutMediator(view.findViewById(R.id.tab_layout), viewPager,
                (tab, position) -> tab.setText(mAdapter.getItemTitle(position))
        ).attach();

        builder.setView(view)
                .setTitle(R.string.dialog_usertrust_message)
                .setPositiveButton(R.string.dialog_usertrust_positive, (dialog, which)
                        -> UserTrustManager.getInstance().setCertificateTrust(certificateChain, UserTrustManager.Trust.TRUSTED))
                .setNegativeButton(R.string.dialog_usertrust_negative, (dialog, which)
                        -> UserTrustManager.getInstance().setCertificateTrust(certificateChain, UserTrustManager.Trust.UNTRUSTED))
                .setNeutralButton(R.string.dialog_usertrust_neutral, null)
        ;

        return builder.create();
    }

    public static class CertificateFragment extends Fragment {
        X509Certificate mCertificate;

        public static CertificateFragment newInstance(X509Certificate certificate) {
            return new CertificateFragment()
                    .setup(certificate);
        }

        CertificateFragment setup(X509Certificate certificate) {
            mCertificate = certificate;
            return this;
        }

        @Nullable
        @Override
        public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
            return inflater.inflate(R.layout.dialog_certtrust_certificate, container, false);
        }

        @Override
        public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
            super.onViewCreated(view, savedInstanceState);

            view.<TextView>findViewById(R.id.certificate_subject_dn).setText(mCertificate.getSubjectDN().toString());
            view.<TextView>findViewById(R.id.certificate_issuer_dn).setText(mCertificate.getIssuerDN().toString());
            view.<TextView>findViewById(R.id.certificate_not_before).setText(mCertificate.getNotBefore().toString());
            view.<TextView>findViewById(R.id.certificate_not_after).setText(mCertificate.getNotAfter().toString());

            String publicKeyInfo = CertUtils.getPublicKeyDescription(mCertificate.getPublicKey());
            view.<TextView>findViewById(R.id.certificate_public_key_info).setText(publicKeyInfo);

            view.<TextView>findViewById(R.id.certificate_fingerprint).setText(
                    Utils.bytesToHex(UserTrustManager.certificateChainFingerprint(new X509Certificate[]{mCertificate}, "SHA256")));
        }
    }

    static class CertificateListAdapter extends FragmentStateAdapter {
        private final Fragment mFragment;
        private final X509Certificate[] mCachedCertificateChain;

        public CertificateListAdapter(Fragment fragment, X509Certificate[] cachedCertificateChain) {
            super(fragment);

            mFragment = fragment;
            mCachedCertificateChain = cachedCertificateChain;
        }

        @NonNull
        @Override
        public Fragment createFragment(int position) {
            return CertificateFragment.newInstance(mCachedCertificateChain[position]);
        }

        @Override
        public int getItemCount() {
            return mCachedCertificateChain.length;
        }

        public CharSequence getItemTitle(int position) {
            if (position == getItemCount() - 1)
                return mFragment.getString(R.string.dialog_usertrust_tab_root);

            return mFragment.getString(R.string.dialog_usertrust_tab_cert, position);
        }
    }
}
