package pt.ulisboa.ist.gsd.da.token16;

import android.Manifest;
import android.app.Activity;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.util.Log;

import com.google.zxing.Result;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import me.dm7.barcodescanner.zxing.ZXingScannerView;

public class MainActivity extends Activity {

    private static final String TAG = "Token16";

    private static final int ZXING_CAMERA_PERM_REQ = 12345;

    private ZXingScannerView dm7;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dm7 = new ZXingScannerView(this);
        setContentView(dm7);
        //setContentView(R.layout.activity_main);
    }

    private static final String M1_B64 =
            "r4IBtaGCAbEwggGtBIIBqTCCAaWiggF/MIIBewQgvY8EWeBRsuQkIJHvM5xBtMXgW2rBosw8\n" +
            "uhRZnoqfdRgEWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIUM2fSkgK4AZRdxCw7hb8mL\n" +
            "8J+EC+clPdqpbaA/tu3PUF8MgC5sYwFkW7nlAK865ZOBxQNE/cco3TTFjZMMLU0EIN1kNPUX\n" +
            "h8eF2RsecNUYTVk9WfSI6Pfk62jETdv0LUWdBFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
            "AAToFWhBwnVm9g665eoRvFpH93URdF8tNK62GJznPoloSyQJ9OfUolY7hssiOT3I9Ra/BxwP\n" +
            "XFCrzAROLRVp3PDNBEcwRQIgGCzDxxNnxwsGZCGIK1pBlkfLPpG0GrbDDnnkd2AQ8ZwCIQCB\n" +
            "LWoFElI9zGAbfckpDRY0y6xi+/wuMBYZON2HAla6UgQQSMjaLYoo8+TXGAoroethoQQgw+7v\n" +
            "4pOF6KFFolgNzB32fU9rqfrLPa2aUkB7Ij3Lw0wEICojvEU7+O3bEu1CZ+jpaDfTkuF3CXnF\n" +
            "UX18Os1v538Y"; // init_ap()
    private static final String M2_B64 =
            "r2GiXzBdBAwLZ28Ywqphz6z3alUEOBvzBcdmFbncVLJlsX2hO/VBZcCIuhmIVa83unJ+f5O2\n" +
            "IsaihkhQYqIsS1fIsOFk2zsDDvOsOhB6BBBW0kLgBWeFMmjlYG/v+5djBAEA"; // auth()

    @Deprecated
    private final void testCrypto() {
        byte[] iv = {
                (byte)0x0b, (byte)0x67, (byte)0x6f, (byte)0x18, (byte)0xc2, (byte)0xaa,
                (byte)0x61, (byte)0xcf, (byte)0xac, (byte)0xf7, (byte)0x6a, (byte)0x55
        };
        byte[] sk = {
                (byte)0x48, (byte)0xc8, (byte)0xda, (byte)0x2d,
                (byte)0x8a, (byte)0x28, (byte)0xf3, (byte)0xe4,
                (byte)0xd7, (byte)0x18, (byte)0x0a, (byte)0x2b,
                (byte)0xa1, (byte)0xeb, (byte)0x61, (byte)0xa1
        };
        byte[] ciphertext = {
                (byte)0x1b, (byte)0xf3, (byte)0x05, (byte)0xc7, (byte)0x66, (byte)0x15, (byte)0xb9, (byte)0xdc,
                (byte)0x54, (byte)0xb2, (byte)0x65, (byte)0xb1, (byte)0x7d, (byte)0xa1, (byte)0x3b, (byte)0xf5,
                (byte)0x41, (byte)0x65, (byte)0xc0, (byte)0x88, (byte)0xba, (byte)0x19, (byte)0x88, (byte)0x55,
                (byte)0xaf, (byte)0x37, (byte)0xba, (byte)0x72, (byte)0x7e, (byte)0x7f, (byte)0x93, (byte)0xb6,
                (byte)0x22, (byte)0xc6, (byte)0xa2, (byte)0x86, (byte)0x48, (byte)0x50, (byte)0x62, (byte)0xa2,
                (byte)0x2c, (byte)0x4b, (byte)0x57, (byte)0xc8, (byte)0xb0, (byte)0xe1, (byte)0x64, (byte)0xdb,
                (byte)0x3b, (byte)0x03, (byte)0x0e, (byte)0xf3, (byte)0xac, (byte)0x3a, (byte)0x10, (byte)0x7a
        };
        byte[] tag = {
                (byte)0x56, (byte)0xd2, (byte)0x42, (byte)0xe0,
                (byte)0x05, (byte)0x67, (byte)0x85, (byte)0x32,
                (byte)0x68, (byte)0xe5, (byte)0x60, (byte)0x6f,
                (byte)0xef, (byte)0xfb, (byte)0x97, (byte)0x63
        };
        byte[] ad = {0x00};

        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            // store sk_enc
            SecretKey secretKey = new SecretKeySpec(sk, "AES");
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter param = new KeyProtection
                    .Builder(KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();
            ks.setEntry("foo", secretKeyEntry, param);
            //KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) ks.getEntry("foo", null);

            Log.v(TAG, "Listing aliases...");
            Enumeration<String> aliases = ks.aliases();
            for (; aliases.hasMoreElements();) {
                Log.v(TAG, "alias: " + aliases.nextElement());
            }
            //ks.store(null);

            // Java decryption expects: ciphertext||tag
            byte[] ct = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ct, 0, ciphertext.length);
            System.arraycopy(tag, 0, ct, ciphertext.length, tag.length);

            // get fresh key from keystore
            KeyStore ks2 = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            SecretKey secretKey2 = (SecretKey) ks.getKey("foo", null);
            Log.v(TAG, "key extracted? " + (secretKey2!=null));

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "AndroidKeyStoreBCWorkaround");
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey2, params);
            if (ad != null) {
                cipher.updateAAD(ad);
            }
            byte[] plaintext = cipher.doFinal(ct);

            Log.v(TAG, "result ok? " + (plaintext != null));
            Log.d(TAG, new String(plaintext));
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        dm7.setResultHandler(resultHandler);
        if (hasCameraPermission(true)) {
            dm7.startCamera();
        }
        //RequestProcessor.processRequest("sem texto");//TEMP

        //RequestProcessor.processRequest(M1_B64);
        //RequestProcessor.processRequest(M2_B64);

        for (Provider e : Security.getProviders()) {
            Log.v(TAG, "provider: " + e.getName());
        }
        Log.v(TAG, "Default Provider: " + KeyStore.getDefaultType());



        String tmpStr =
                "r4IBtaKCAbEwggGtBAwzJyEJoPGxTDT30/kEggGGFoAH66md+GoFapYD5aSOPREKM5c8A3UD\n" +
                "ILoiI0+ZHb5CFwjyN7gRcLI2tZMM5iKmrgzqbnS7DIACHeZ4T6fyz2hg3JxOucp/ohZ/jrVQ\n" +
                "YhuUQcaMb9Vzcu4RKy0x8PaOh5Vm/AavR0ckMpRTwWE6Vye5sZ2HD1lVfC5uqGi7na1XjSRM\n" +
                "05KZ3+gzcha2UhLgFPrkGKG6sfX2US3k3DTANZVJL7WtXekWjWYqpR2Xio78y5SKdEKLl5Rg\n" +
                "RjtgiV1927CXMzMreQYmDPJY8NfsF1Ys3Qc8NBh17vnj1R7TtaIfzHzQrj/OdTOW+2bGgE/m\n" +
                "7i27iSSZocN+OtOuKXZdingaHvZ5N/GjF/sUeR6j3QfwCyl4uw4618Ea5nPoXAqERZ8WlbM6\n" +
                "bGATJcU86BSzP5D1k+W5nZomrp5+2SeH4hm9lKe1PxHtOR4iVBbsQyVLtlGiSeJ0/BUwBMoq\n" +
                "O3MWS8iDBhV1yNiK9vZ8WYqfIVB424+iZcxVQs5dwR9SPB7LPrT05giCBBAbnI17ifxiDLfg\n" +
                "HmZuKU9TBAEA";
        //RequestProcessor.processRequest(this, tmpStr);



        //RequestProcessor.RequestData requestData = new RequestProcessor.RequestData(tmpStr);
        //new RequestProcessor(this, dismiss).execute(requestData);



        //testCrypto();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (hasCameraPermission(false)) {
            dm7.stopCamera();
        }
    }

    /**
     * Checks if the app has the permission to use the camera.
     * Can request the permission if it doesn't have it already.
     */
    private boolean hasCameraPermission(boolean requestPerm) {
        int cameraPermState = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA);
        if (PackageManager.PERMISSION_GRANTED == cameraPermState) {
            return true;
        }

        if (requestPerm) {
            String[] permissions = new String[]{
                    Manifest.permission.CAMERA
            };
            ActivityCompat.requestPermissions(this, permissions, ZXING_CAMERA_PERM_REQ);
        }

        return false;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           @NonNull String[] perms,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, perms, grantResults);
        switch (requestCode) {
            case ZXING_CAMERA_PERM_REQ:
                if (perms.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    dm7.startCamera();
                }
        }
    }

    private ZXingScannerView.ResultHandler resultHandler = new ZXingScannerView.ResultHandler() {

        @Override
        public void handleResult(Result result) {
            RequestProcessor.RequestData requestData;

            requestData = new RequestProcessor.RequestData(result.getText());
            new RequestProcessor(MainActivity.this, dismiss).execute(requestData);
        }
    };

    // pass this into the worker to restart camera 'on dismiss'
    private DialogInterface.OnDismissListener dismiss = new DialogInterface.OnDismissListener() {

        @Override
        public void onDismiss(DialogInterface dialog) {
            Log.d(TAG, "dialog dismissed");
            dm7.resumeCameraPreview(resultHandler);
        }
    };
}
