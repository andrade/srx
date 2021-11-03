package pt.ulisboa.ist.gsd.da.token16;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.util.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Handles certificates and keys conversions.
 *
 * @author Daniel Andrade
 */
final public class CryptoManipulator {

    public static class DER {

        // EC not available in API 23, using external provider (BC via SpongyCastle)
        public static final String EC_PROVIDER = "BC";

        @Nullable
        public static PublicKey fromBytes(@NonNull byte[] derEncodedKey) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derEncodedKey);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EC", EC_PROVIDER);
                return keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
                return null;
            }
        }

        @Nullable
        public static byte[] toBytes(@NonNull PublicKey pub) {
            return pub.getEncoded();
        }
    }

    public static class PEM {

        private static final String PUB_DELIMITATION_BEGIN = "-----BEGIN PUBLIC KEY-----";
        private static final String PUB_DELIMITATION_END = "-----END PUBLIC KEY-----";

        @Nullable
        public static PublicKey fromStr(@NonNull String pemEncodedKey) {

            // remove BEGIN/END delimitation
            String noPrefix = pemEncodedKey.substring(pemEncodedKey.indexOf('\n') + 1);
            String noSuffix = noPrefix.substring(0, noPrefix.indexOf('-'));

            byte[] derEncodedKey = Base64.decode(noSuffix, Base64.NO_WRAP);

            return DER.fromBytes(derEncodedKey);
        }

        @Nullable
        public static String toStr(@NonNull PublicKey pub) {
            byte[] derEncoded = DER.toBytes(pub);
            if (derEncoded == null) {
                return null;
            }
            String base64Encoded = Base64.encodeToString(derEncoded, Base64.NO_WRAP);

            return new StringBuilder()
                    .append(PUB_DELIMITATION_BEGIN).append('\n')
                    .append(base64Encoded).append('\n')
                    .append(PUB_DELIMITATION_END).append('\n')
                    .toString();
        }
    }
}
