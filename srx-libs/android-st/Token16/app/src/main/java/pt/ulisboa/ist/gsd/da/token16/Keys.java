package pt.ulisboa.ist.gsd.da.token16;

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class Keys {

    private static final String TAG = "Keys";

    /** Name of the keystore. */
    private static final String KS = "SRX";

    /** The provider of the keystore. */
    private static final String PROVIDER = SecurityConst.KEYSTORE_TYPE;

    private static final String ENC_KEY_ALIAS = "sk_enc";
    private static final String MAC_KEY_ALIAS = "sk_mac";

    //TODO  Need reset/init functionality for the KeyStore (e.g. when receive init, overwrite...)
    //NOTE  probably need Client-Phone protocol with init if not init'd; and overwrite whether init or not.

    private static SecretKey getSK(String alias) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            Log.e(TAG, "Could not load KS with name: " + KS);
            return null;
        }

        try {
            Log.v(TAG, "Aliases in keystore:");
            Enumeration<String> aliases = ks.aliases();
            for (; aliases.hasMoreElements();) {
                Log.v(TAG, "alias: " + aliases.nextElement());
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            return (SecretKey) ks.getKey(alias, null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static SecretKey putSK(String alias, byte[] sk, String algorithm) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            Log.e(TAG, "Could not load KS with name: " + KS);
            return null;
        }

        SecretKey secretKey = new SecretKeySpec(sk, algorithm);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        try {
            KeyStore.ProtectionParameter param = null;
            if (algorithm.equals(SecurityConst.ENC_ALGO)) {
                param = new KeyProtection
                        .Builder(KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();
            } else if (algorithm.equals(SecurityConst.MAC_ALGO)){
                param = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build();
            } else {
                Log.e(TAG, "bad algo: " + algorithm);
                return null;
            }
            ks.setEntry(alias, secretKeyEntry, param);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        }

        return secretKey;
    }

    /**
     * Retrieves the secret key for encryption from the keystore.
     *
     * @return  The secret key for encryption, or null if not found or on error.
     */
    public static SecretKey getEncKey() {
        return getSK(ENC_KEY_ALIAS);
    }

    /**
     * Stores the secret key for encryption in the keystore.
     *
     * @param sk  The secret key for encryption
     * @return    Returns the secret key for encryption, in internal format, on success; or null.
     */
    public static SecretKey setEncKey(byte[] sk) {
        return putSK(ENC_KEY_ALIAS, sk, SecurityConst.ENC_ALGO);
    }

    /**
     * Retrieves the secret key for MAC'ing from the keystore.
     *
     * @return  The secret key, or null if not found or on error.
     */
    public static SecretKey getMacKey() {
        return getSK(MAC_KEY_ALIAS);
    }

    /**
     * Stores the secret key for MAC'ing in the keystore.
     *
     * @param sk  The secret key
     * @return    Returns the secret key, in internal format, on success; or null.
     */
    public static SecretKey setMacKey(byte[] sk) {
        return putSK(MAC_KEY_ALIAS, sk, SecurityConst.MAC_ALGO);
    }
}
