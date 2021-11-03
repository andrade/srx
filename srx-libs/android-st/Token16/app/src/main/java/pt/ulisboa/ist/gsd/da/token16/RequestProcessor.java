package pt.ulisboa.ist.gsd.da.token16;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1SequenceParser;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.util.ASN1Dump;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.ulisboa.ist.gsd.da.token16.database.Platform;

//TODO  Remove activity_layout since not used.
class RequestProcessor extends AsyncTask<RequestProcessor.Foo, Void, RequestProcessor.Foo> {

    private static final String TAG = "RequestProcessor";

    private static final String CRYPTO_PROVIDER = SecurityConst.CRYPTO_PROVIDER;

    /** Fake response data to display on internal error. */
    private static final ResponseData INTERNAL_ERROR_RD = new ResponseData("Internal error")
            .setNextStep(NextStep.CONCLUDE)
            .setRC(ResponseCode.FAILURE);

    /** For accessing application and activity contexts for database and dialogs respectively. */
    private static WeakReference<Activity> activity;

    private static DialogInterface.OnDismissListener dismiss;

    public RequestProcessor(Activity activity, DialogInterface.OnDismissListener dismissListener) {
        this.activity = new WeakReference<>(Objects.requireNonNull(activity));
        this.dismiss = dismissListener;
    }

    // meant to bootstrap new tasks from within, when activity + dismiss listener are already set
    private RequestProcessor() {
        // uses already-set fields
    }

    private ResponseData postProcessAddP(ResponseData rd) {
        switch (rd.getRC()) {
            case SUCCESS:
                if (rd.getObject() instanceof Platform) {
                    Context appContext = activity.get().getApplicationContext();
                    LocalDB.getInstance(appContext).platformDAO().insert((Platform) rd.getObject());
                }
                rd.setMessage("Platform added to the database on the Security Token");
                break;
            default:
                rd.setMessage("Platform not added");
                break;
        }

        byte[] mac = computeResponseMAC(rd.getRC().code(), rd.getNonce());
        if (mac == null) {
            return INTERNAL_ERROR_RD;
        }

        return rd.setMAC(mac).setNextStep(NextStep.CONCLUDE);
    }

    // how requests are presented to the user
    @Deprecated
    private static String preprocess(String message, String code) {
        return message + "\n\nCode:  " + code;
    }

    // how requests are presented to the user
    private static String preProcessDisplayMessage(ResponseData rd) {
        String mac = MyUtil.toHexString(rd.getMAC(), ":");

        return String.format("%s\n\n%s\n\n%s (%s)",
                Objects.toString(rd.getRT(), "<null request type>"),
                Objects.toString(rd.getMessage(), "<null message>"),
                Objects.toString(mac, "<null response MAC>"),
                Objects.toString(rd.getRC(), "<null response code>"));
    }

    /** This is used during intermediate steps to gather feedback from user. */
    @Deprecated
    private void getUserInput(Context context, final ResponseData rd) {
        Objects.requireNonNull(context);
        Objects.requireNonNull(rd);
        Objects.requireNonNull(rd.getRT());

        final AlertDialog.Builder builder = new AlertDialog.Builder(context)
                .setMessage(rd.getMessage());

        switch (rd.getRT()) {
            case ADD_P:
                builder.setPositiveButton(R.string.positive, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.v(TAG, "Add platform: user says OK");
                        postProcessAddP(rd.setRC(ResponseCode.SUCCESS));
                    }
                });
                builder.setNegativeButton(R.string.negative, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.v(TAG, "Add platform: user says NOT OK");
                        postProcessAddP(rd.setRC(ResponseCode.NO_AUTH));
                    }
                });
                break;
            default:
                String error = "Internal error 703, unknown request type: " + rd.getRT().toString();
                Log.e(TAG, error);
                builder.setNeutralButton(R.string.dismiss, null).setMessage(error);
                break;
        }

        builder.show();
    }

    @Deprecated
    private void display(Context context, ResponseData rd) {
        DialogInterface.OnDismissListener dismissListener = new DialogInterface.OnDismissListener() {
            @Override
            public void onDismiss(DialogInterface dialog) {
                Log.d(TAG, "dialog dismissed '");
                // fallback: camera not restarted in this case
            }
        };
        display(context, dismissListener, rd);
    }

    @Deprecated
    private void display(Context context,
                         @NonNull DialogInterface.OnDismissListener dismiss,
                         final ResponseData rd) {
        final AlertDialog.Builder builder = new AlertDialog.Builder(context)
                .setOnDismissListener(dismiss);

        if (rd.getRT() == null || rd.getMAC() == null) {
            String error = "Internal error 701";
            Log.e(TAG, error);
            builder.setNeutralButton(R.string.dismiss, null).setMessage(error).show();
            return;
        }

        builder.setMessage(preprocess(rd.getMessage(), MyUtil.toHexString(rd.getMAC(), ":")));
        //TODO should only display some digits, not all as we currently do

        switch (rd.getRT()) {
            case AUTH:
                builder.setPositiveButton(R.string.proceed, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.v(TAG, "Proceed with auth");//TODO
                    }
                });
                builder.setNegativeButton(R.string.reject, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.v(TAG, "Reject auth");//TODO
                    }
                });
                break;
            case INIT_FIRST_P:
                builder.setPositiveButton(R.string.positive, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.v(TAG, "Add AP action OK");//TODO
                    }
                });
                builder.setNegativeButton(R.string.negative, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.v(TAG, "Add AP action NOT OK");//TODO
                    }
                });
                break;
            case ADD_P:
                builder.setPositiveButton(R.string.positive, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.v(TAG, "Add RP action OK");//TODO
                        postProcessAddP(rd);
                    }
                });
                builder.setNegativeButton(R.string.negative, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.v(TAG, "Add RP action NOT OK");//TODO
                    }
                });
                break;
            default:
                String error = "Internal error 702, unknown request type: " + rd.getRT().toString();
                Log.e(TAG, error);
                builder.setNeutralButton(R.string.dismiss, null).setMessage(error);
                break;
        }

        builder.show();
    }

    //TODO    Main and only one, deprecate/remove others
    private void display2(final ResponseData rd) {
        assert rd != null;

        String s;
        NextStep nextStep = Objects.requireNonNull(rd.getNextStep());

        AlertDialog.Builder builder = new AlertDialog.Builder(activity.get());
        //builder.setMessage(rd.getMessage());

        switch (nextStep) {
            case AUTH_GET_USER_INPUT:
                builder.setPositiveButton(R.string.positive, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String s = "Operation authorized by user";
                        Log.v(TAG, s);
                        rd.setMessage(s).setRC(ResponseCode.SUCCESS).setNextStep(NextStep.COMPUTE_MAC);
                        new RequestProcessor().execute(rd);
                    }
                }).setNegativeButton(R.string.negative, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        String s = "Operation rejected by user";
                        Log.v(TAG, s);
                        rd.setMessage(s).setRC(ResponseCode.NO_AUTH).setNextStep(NextStep.COMPUTE_MAC);
                        new RequestProcessor().execute(rd);
                    }
                }).setMessage(rd.getMessage());
                break;
            case ADD_P_GET_USER_INPUT:
                builder.setPositiveButton(R.string.positive, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.v(TAG, "Add RP: user says OK");
                        rd.setRC(ResponseCode.SUCCESS).setNextStep(NextStep.ADD_P_INSERT_DB);
                        new RequestProcessor().execute(rd);
                    }
                }).setNegativeButton(R.string.negative, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.v(TAG, "Add RP: user says NOT OK");
                        String s = "Add platform:\n\nOperation rejected by user";
                        rd.setMessage(s).setRC(ResponseCode.NO_AUTH).setNextStep(NextStep.COMPUTE_MAC);
                        new RequestProcessor().execute(rd);
                    }
                }).setMessage(rd.getMessage());
                break;
            case CONCLUDE:
                s = preProcessDisplayMessage(rd);
                builder.setNeutralButton(R.string.dismiss, null)
                        .setOnDismissListener(dismiss)
                        .setMessage(s);
                break;
            default:
                String error = "Internal error 703, unknown request type: " + rd.getRT().toString();
                Log.e(TAG, error);
                builder.setNeutralButton(R.string.dismiss, null).setMessage(error);
                //FIXME   restart camera with dismiss listener?
                break;
        }

        builder.show();
    }

    // preProcessResponse, postProcessResponse
    private ResponseData processResponse(ResponseData rd) {
        switch (rd.getNextStep()) {
            case ADD_P_INSERT_DB:
                return postProcessAddP(rd);
            case COMPUTE_MAC:
                byte[] mac = computeResponseMAC(rd.getRC().code(), rd.getNonce());
                if (mac == null) {
                    return INTERNAL_ERROR_RD;
                }
                return rd.setMAC(mac).setNextStep(NextStep.CONCLUDE);
            case CONCLUDE:
                // ready to be displayed, method shouldn't be called when already in this stage
                //throw new IllegalStateException("Bad step: `CONCLUDE`");
                return rd;
            default:
                String exception = "Unsupported next step (" + rd.getNextStep().toString() + ")";
                throw new UnsupportedOperationException(exception);
        }
    }

    /**
     * Encrypts the plaintext (AEAD).
     *
     * NOTE: The encryption concatenates the 16-byte tag to the ciphertext.
     *
     * @param key         The secret key for encryption/decryption
     * @param iv          The 12-byte IV
     * @param plaintext   The plaintext to encrypt
     * @param ad          The optional associated data (not encrypted, but authenticated)
     *
     * @return            Returns the ciphertext||tag on success, or null on error.
     *
     * @see #decrypt(byte[], byte[], byte[], byte[])
     */
    @Nullable
    private static byte[] encrypt(@NonNull byte[] key, @NonNull byte[] iv,
                                  @NonNull byte[] plaintext,
                                  @Nullable byte[] ad) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(iv);
        Objects.requireNonNull(plaintext);

        try {
            Cipher cipher = Cipher.getInstance(SecurityConst.ENC_TRANSFORMATION, CRYPTO_PROVIDER);
            SecretKey secretKey = new SecretKeySpec(key, SecurityConst.ENC_ALGO);
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
            if (ad != null) {
                cipher.updateAAD(ad);
            }
            // Java encryption returns: ciphertext||tag
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] encrypt(@NonNull SecretKey key,
                                  @NonNull byte[] iv,
                                  @NonNull byte[] plaintext,
                                  @Nullable byte[] ad) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(iv);
        Objects.requireNonNull(plaintext);

        try {
            Cipher cipher = Cipher.getInstance(SecurityConst.ENC_TRANSFORMATION, CRYPTO_PROVIDER);
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            if (ad != null) {
                cipher.updateAAD(ad);
            }
            // Java encryption returns: ciphertext||tag
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts the ciphertext (AEAD).
     *
     * @param key         The secret key for encryption/decryption
     * @param iv          The 12-byte IV
     * @param ciphertext  The ciphertext to decrypt
     * @param tag         The 16-byte tag
     * @param ad          The additional data
     *
     * @return            Returns the plaintext on success, or null on error.
     *
     * @see #decrypt(byte[], byte[], byte[], byte[])
     */
    @Nullable
    private static byte[] decrypt(@NonNull byte[] key, @NonNull byte[] iv,
                                  @NonNull byte[] ciphertext, @NonNull byte[] tag,
                                  @Nullable byte[] ad) {
        // Java decryption expects: ciphertext||tag
        byte[] ct = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, ct, 0, ciphertext.length);
        System.arraycopy(tag, 0, ct, ciphertext.length, tag.length);

        return decrypt(key, iv, ct, ad);
    }

    /**
     * Decrypts the ciphertext (AEAD).
     *
     * @param key         The secret key for encryption/decryption
     * @param iv          The 12-byte IV
     * @param ctPlusTag   The ciphertext||tag
     * @param ad          The additional data
     *
     * @return            Returns the plaintext on success, or null on error.
     *
     * @see #decrypt(byte[], byte[], byte[], byte[], byte[])
     */
    @Nullable
    private static byte[] decrypt(@NonNull byte[] key, @NonNull byte[] iv,
                                  @NonNull byte[] ctPlusTag,
                                  @Nullable byte[] ad) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(iv);
        Objects.requireNonNull(ctPlusTag);

        try {
            Cipher cipher = Cipher.getInstance(SecurityConst.ENC_TRANSFORMATION, CRYPTO_PROVIDER);
            SecretKey secretKey = new SecretKeySpec(key, SecurityConst.ENC_ALGO);
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
            if (ad != null) {
                cipher.updateAAD(ad);
            }
            return cipher.doFinal(ctPlusTag);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] decrypt(@NonNull SecretKey key, @NonNull byte[] iv,
                                  @NonNull byte[] ciphertext, @NonNull byte[] tag,
                                  @Nullable byte[] ad) {
        // Java decryption expects: ciphertext||tag
        byte[] ct = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, ct, 0, ciphertext.length);
        System.arraycopy(tag, 0, ct, ciphertext.length, tag.length);

        return decrypt(key, iv, ct, ad);
    }

    private static byte[] decrypt(@NonNull SecretKey key,
                                  @NonNull byte[] iv,
                                  @NonNull byte[] ctPlusTag,
                                  @Nullable byte[] ad) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(iv);
        Objects.requireNonNull(ctPlusTag);

        try {
            Cipher cipher = Cipher.getInstance(SecurityConst.ENC_TRANSFORMATION, CRYPTO_PROVIDER);
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            if (ad != null) {
                cipher.updateAAD(ad);
            }
            return cipher.doFinal(ctPlusTag);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    // returns true if the signature is legit
    public static boolean verifySignature(byte[] data, byte[] sig, PublicKey pub) {
        try {
            Signature signature = Signature
                    .getInstance(SecurityConst.SIG_ALGO, SecurityConst.EC_SIG_PROVIDER);
            signature.initVerify(pub);
            signature.update(data);
            return signature.verify(sig);  // TODO reusable, read doc of `verify`
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    /** Computes the response MAC for displaying to the user. */
    private static byte[] computeResponseMAC(byte responseCode, byte[] nonce) {
        byte[] response = new byte[] {responseCode};
        SecretKey skMac = Keys.getMacKey();
        if (skMac == null) {
            Log.e(TAG, "Could not retrieve sk_mac");
            return null;
        }
        return mac(skMac, nonce, response);
    }

    // never reaches this stage unless client has the secret keys (implicitly, platform has access)
    private static ResponseData handle_message_auth(ASN1Sequence sequence) throws IOException {
        Log.d(TAG, ASN1Dump.dumpAsString(sequence, true));
        ASN1SequenceParser parser = sequence.parser();

        //DERIA5String string = DERIA5String.getInstance(parser.readObject());
        DERUTF8String string = DERUTF8String.getInstance(parser.readObject());

        String displayText = string.getString();

        Log.v(TAG, "display text received is: " + displayText);

        // print all PIDs in database, TEMP
        Context appContext = activity.get().getApplicationContext();
        List<Platform> list = LocalDB.getInstance(appContext).platformDAO().getAll();
        for (Platform e : list) {
            Log.v(TAG, "e: " + e.toString());
        }

        String msg = "Authorize the operation?\n\n" + displayText;
        return new ResponseData(msg)
                .setNextStep(NextStep.AUTH_GET_USER_INPUT)
                .setRT(RequestType.AUTH);
    }

    // Stores keys in KS.
    // Returns true on success, false otherwise.
    private static boolean storeKeys(byte[] skEnc, byte[] skMac) {
        if (Keys.setEncKey(skEnc) == null) {
            Log.e(TAG, "Could not store sk_enc");
            return false;
        }
        if (Keys.setMacKey(skMac) == null) {
            Log.e(TAG, "Could not store sk_mac");
            return false;
        }

        return true;
    }

    /*
    TokenInitAP ::= SEQUENCE {
		platform-id     OCTET STRING,           -- details of the AP
		ras-sig         OCTET STRING,           -- signature from the RAS

		sk-enc          OCTET STRING,           -- secret key for encryption
		sk-mac          OCTET STRING            -- secret key for MAC'ing
	}
	*/
    private static ResponseData handle_message_init_ap(ASN1Sequence sequence) throws IOException {
        Log.d(TAG, ASN1Dump.dumpAsString(sequence, true));
        ASN1SequenceParser parser = sequence.parser();

        byte[] platformIdOS = ASN1OctetString.getInstance(parser.readObject()).getOctets();
        byte[] sigRasOS = ASN1OctetString.getInstance(parser.readObject()).getOctets();
        byte[] skEnc= ASN1OctetString.getInstance(parser.readObject()).getOctets();
        byte[] skMac= ASN1OctetString.getInstance(parser.readObject()).getOctets();

        PublicKey pub = CryptoManipulator.PEM.fromStr(SecurityConst.RAS_PUB_PEM);
        if (pub == null) {
            return INTERNAL_ERROR_RD;
        }
        if (!verifySignature(platformIdOS, sigRasOS, pub)) {
            String error = "Invalid signature by the Remote Attestation Service";
            Log.e(TAG, error);
            return new ResponseData()
                    .setMessage(error)
                    .setNextStep(NextStep.CONCLUDE)
                    .setRC(ResponseCode.FAILURE)
                    .setRT(RequestType.INIT_FIRST_P);
        }

        byte[] commNonce = null;
        byte[] commPub = null;
        byte[] sealNonce = null;
        byte[] sealPub = null;
        BigInteger apid = null;

        try (ASN1InputStream inputStream = new ASN1InputStream(platformIdOS)) {
            ASN1Sequence root = ASN1Sequence.getInstance(inputStream.readObject());
            Log.d(TAG, ASN1Dump.dumpAsString(root, true));
            ASN1SequenceParser rootParser = root.parser();

            commNonce = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            commPub = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            sealNonce = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            sealPub = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            apid = ASN1Integer.getInstance(rootParser.readObject()).getPositiveValue();

        } catch (IOException e) {
            Log.e(TAG, "Internal error parsing DER-encoded PlatformID", e);
            String error = "Internal error";
            return new ResponseData(error, ResponseCode.FAILURE, RequestType.INIT_FIRST_P)
                    .setNextStep(NextStep.CONCLUDE);
        }

        String apidStr = String.format("%016x", apid);
        Log.v(TAG, "Platform ID = " + apidStr);

        PublicKey commPubKey = CryptoManipulator.DER.fromBytes(commPub);
        if (commPubKey == null) {
            String error = "Error decoding the platform communication public key (PCPK)";
            Log.e(TAG, error);
            return INTERNAL_ERROR_RD;
        }

        if (!storeKeys(skEnc, skMac)) {
            String error = "Internal error";
            return INTERNAL_ERROR_RD;
        }

        Platform ap = new Platform(apid, commPubKey, Platform.Status.ACCEPTED);
        Context appContext = activity.get().getApplicationContext();

        // clear database of all platforms
        List<Platform> list = LocalDB.getInstance(appContext).platformDAO().getAll();
        for (Platform e : list) {
            LocalDB.getInstance(appContext).platformDAO().delete(e);
        }

        LocalDB.getInstance(appContext).platformDAO().insert(ap);

        return new ResponseData()
                .setMessage("Platform successfully paired with the Security Token")
                .setNextStep(NextStep.CONCLUDE)
                .setRC(ResponseCode.SUCCESS)
                .setRT(RequestType.INIT_FIRST_P);
    }

    private ResponseData handle_message_init_rp(ASN1Sequence sequence) throws IOException {
        Log.d(TAG, ASN1Dump.dumpAsString(sequence, true));
        ASN1SequenceParser parser = sequence.parser();

        byte[] platformIdOS = ASN1OctetString.getInstance(parser.readObject()).getOctets();
        byte[] sigRasOS = ASN1OctetString.getInstance(parser.readObject()).getOctets();

        PublicKey pub = CryptoManipulator.PEM.fromStr(SecurityConst.RAS_PUB_PEM);
        if (pub == null) {
            return INTERNAL_ERROR_RD;
        }
        if (!verifySignature(platformIdOS, sigRasOS, pub)) {
            String error = "Invalid signature by the Remote Attestation Service";
            Log.e(TAG, error);
            return new ResponseData(error, ResponseCode.FAILURE, RequestType.ADD_P)
                    .setNextStep(NextStep.CONCLUDE);
        }

        byte[] commNonce = null;
        byte[] commPub = null;
        byte[] sealNonce = null;
        byte[] sealPub = null;
        BigInteger pid = null;

        try (ASN1InputStream inputStream = new ASN1InputStream(platformIdOS)) {
            ASN1Sequence root = ASN1Sequence.getInstance(inputStream.readObject());
            Log.d(TAG, ASN1Dump.dumpAsString(root, true));
            ASN1SequenceParser rootParser = root.parser();

            commNonce = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            commPub = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            sealNonce = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            sealPub = ASN1OctetString.getInstance(rootParser.readObject()).getOctets();
            pid = ASN1Integer.getInstance(rootParser.readObject()).getPositiveValue();

        } catch (IOException e) {
            Log.e(TAG, "Internal error parsing DER-encoded PlatformID", e);
            String error = "Internal error";
            return new ResponseData(error, ResponseCode.FAILURE, RequestType.ADD_P)
                    .setNextStep(NextStep.CONCLUDE);
        }

        String pidStr = String.format("%016x", pid);
        Log.v(TAG, "Platform ID = " + pidStr);

        PublicKey commPubKey = CryptoManipulator.DER.fromBytes(commPub);
        if (commPubKey == null) {
            String error = "Error decoding the communication public key of the new platform";
            Log.e(TAG, error);
            return INTERNAL_ERROR_RD;
        }

        Platform newRP = new Platform(pid, commPubKey, Platform.Status.ACCEPTED);

        String msg = "Give this platform access to your data?\n\nPlatform ID = " + pidStr;
        return new ResponseData(msg)
                .setNextStep(NextStep.ADD_P_GET_USER_INPUT)
                .setRT(RequestType.ADD_P)
                .setObject(newRP);
    }

    private ResponseData handle_message_remove(ASN1Sequence sequence) throws IOException {
        Log.d(TAG, ASN1Dump.dumpAsString(sequence, true));
        ASN1SequenceParser parser = sequence.parser();

        BigInteger rpid = ASN1Integer.getInstance(parser.readObject()).getPositiveValue();

        Context appContext = activity.get().getApplicationContext();
        List<Platform> list = LocalDB.getInstance(appContext).platformDAO().getAll();

        Platform rp = null;

        for (Platform e : list) {
            if (e.pid.equals(rpid)) {
                rp = e;
            }
        }

        if (rp == null) {
            final String s = String.format("The platform (%016x) is not in the database", rpid);
            Log.v(TAG, s);
            return new ResponseData(s)
                    .setNextStep(NextStep.CONCLUDE)
                    .setRC(ResponseCode.SUCCESS)
                    .setRT(RequestType.REMOVE_P);
            //NOTE: Possible to remove from ST without removing from client
            //      (e.g. user does not enter response code in client, or system crashes)
            //      so we still display the SUCCESS RC for client to remove this platform.
        }

        LocalDB.getInstance(appContext).platformDAO().delete(rp);

        final String s = String.format("Removed platform (%016x)", rp.pid);
        Log.v(TAG, s);
        return new ResponseData(s, NextStep.CONCLUDE, ResponseCode.SUCCESS, RequestType.REMOVE_P);
    }

    /**
     * Parses the message proper.
     *
     * Decodes the ASN.1 inner message, processes the request, and builds the response.
     *
     * @param input  The DER-encoded message
     * @return       The response to the incoming request.
     */
    @NonNull
    private ResponseData parseMessage(@NonNull byte[] input) {
        byte[] nonce;
        ResponseData rd;

        try (ASN1InputStream inputStream = new ASN1InputStream(input)) {
            ASN1Sequence root = ASN1Sequence.getInstance(inputStream.readObject()); // TokenMessage
            Log.d(TAG, ASN1Dump.dumpAsString(root, true));
            ASN1SequenceParser rootParser = root.parser();

            ASN1TaggedObject request = ASN1TaggedObject.getInstance(rootParser.readObject());
            ASN1OctetString nonceOS = ASN1OctetString.getInstance(rootParser.readObject());

            Log.d(TAG, "Inner message tag no. is " + request.getTagNo());
            switch (request.getTagNo()) {
                case 1:
                    rd = handle_message_auth(ASN1Sequence.getInstance(request.getObject()));
                    break;
                case 2:
                    rd = handle_message_init_ap(ASN1Sequence.getInstance(request.getObject()));
                    break;
                case 3:
                    rd = handle_message_init_rp(ASN1Sequence.getInstance(request.getObject()));
                    break;
                case 4:
                    rd = handle_message_remove(ASN1Sequence.getInstance(request.getObject()));
                    break;
                default:
                    Log.e(TAG, "Message tag out of bounds: " + request.getTagNo());
                    return INTERNAL_ERROR_RD;
            }

            nonce = nonceOS.getOctets();
        } catch (IOException e) {
            e.printStackTrace();
            return INTERNAL_ERROR_RD;
        }

        if (rd.getNextStep() == NextStep.CONCLUDE) {
            byte[] mac = computeResponseMAC(rd.getRC().code(), nonce);
            if (mac == null) {
                return INTERNAL_ERROR_RD;
            }
            return rd.setMAC(mac);
        }

        return rd.setNonce(nonce); // MAC computed later since response code may change
    }

    /**
     * Extracts the cleartext from the given DER-encoded sequence.
     *
     * @param sequence  The ASN.1 DER-encoded input sequence
     * @return  Returns the cleartext on success, or null on error.
     */
    private byte[] handle_cleartext_message(ASN1Sequence sequence) throws IOException {
        ASN1SequenceParser parser = sequence.parser();
        ASN1OctetString cleartext = ASN1OctetString.getInstance(parser.readObject());
        return cleartext.getOctets();
    }

    /**
     * Extracts the plaintext from the given DER-encoded sequence.
     *
     * @param key           The shared secret key for decryption
     * @param sequence      The ASN.1 DER-encoded input sequence
     * @return              Returns the plaintext on success, or null on error.
     *
     * @throws IOException  Unable to read next object from sequence
     */
    private byte[] handle_encrypted_message(SecretKey key, ASN1Sequence sequence) throws IOException {
        ASN1SequenceParser parser = sequence.parser();

        ASN1OctetString nonceOS = ASN1OctetString.getInstance(parser.readObject());
        ASN1OctetString ciphertextOS = ASN1OctetString.getInstance(parser.readObject());
        ASN1OctetString tagOS = ASN1OctetString.getInstance(parser.readObject());
        ASN1OctetString adOS = ASN1OctetString.getInstance(parser.readObject());

        byte[] nonce = nonceOS.getOctets();
        byte[] ciphertext = ciphertextOS.getOctets();
        byte[] tag = tagOS.getOctets();
        byte[] ad = adOS.getOctets();

        byte[] plaintext = decrypt(key, nonce, ciphertext, tag, ad);
        if (null == plaintext) {
            Log.e(TAG, "Error decrypting incoming data");
            return null;
        }

        //Log.d(TAG, "nonce octets = " + toHexString(nonce, ":"));
        //Log.d(TAG, "AD octets = " + toHexString(ad, ""));
        //Log.d(TAG, "plaintext octets = " + toHexString(plaintext, ":"));

        return plaintext;
    }

    /**
     * Decodes ASN.1 outer message.
     *
     * The incoming message may be encrypted or in cleartext.
     * The {@code key} must be given when encrypted.
     *
     * @param input         The DER-encoded message
     * @return              The decrypted data on success, or null on error.
     */
    @Nullable
    private byte[] grab_data(@NonNull byte[] input) {
        try (ASN1InputStream inputStream = new ASN1InputStream(input)) {
            ASN1TaggedObject root = ASN1TaggedObject.getInstance(inputStream.readObject());
            Log.d(TAG, ASN1Dump.dumpAsString(root, true));
            ASN1TaggedObject child = ASN1TaggedObject.getInstance(root.getObject());
            //Log.d(TAG, ASN1Dump.dumpAsString(child, true));

            switch (child.getTagNo()) {
                case 1:
                    return handle_cleartext_message(ASN1Sequence.getInstance(child.getObject()));
                case 2:
                    SecretKey skEnc = Keys.getEncKey();
                    if (skEnc == null) {
                        Log.e(TAG, "Could not retrieve sk_enc");
                        return null;
                    }
                    return handle_encrypted_message(skEnc, ASN1Sequence.getInstance(child.getObject()));
                default:
                    Log.e(TAG, "Device message tag out of bounds: " + child.getTagNo());
                    return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Computes the HMAC of `nonce||input`.
     *
     * @param key    The (32-byte) secret key for the HMAC
     * @param nonce  The (16-byte) nonce that prefixes the data to MAC
     * @param input  The data to MAC
     *
     * @return       The HMAC output, or null on error.
     */
    @Nullable
    private static byte[] mac(@NonNull byte[] key, @NonNull byte[] nonce, @NonNull byte[] input) {
        // data = nonce||input
        byte[] data = new byte[nonce.length + input.length];
        System.arraycopy(nonce, 0, data, 0, nonce.length);
        System.arraycopy(input, 0, data, nonce.length, input.length);

        try {
            Mac mac = Mac.getInstance(SecurityConst.MAC_ALGO);
            SecretKey secretKey = new SecretKeySpec(key, SecurityConst.MAC_ALGO);
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] mac(@NonNull SecretKey key, @NonNull byte[] nonce, @NonNull byte[] input) {
        // data = nonce||input
        byte[] data = new byte[nonce.length + input.length];
        System.arraycopy(nonce, 0, data, 0, nonce.length);
        System.arraycopy(input, 0, data, nonce.length, input.length);

        try {
            Mac mac = Mac.getInstance(SecurityConst.MAC_ALGO);
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Processes the message received from the enclave.
     *
     * The message is decoded – and decrypted if needed – and a response bundle prepared.
     * <s>An encoded response is given to the user to enter on the client side.</s>
     *
     * @param base64data The input data, received from the client, in Base64
     */
    private ResponseData processRequest(String base64data) {
        byte[] rawData = Base64.decode(Objects.requireNonNull(base64data), Base64.NO_WRAP);

        Log.v(TAG, "received data in base64 (" + base64data.length() + "): " + base64data);
        Log.v(TAG, "received data in hex (" + rawData.length + "): "
                + MyUtil.toHexString(rawData, ""));

        byte[] data = grab_data(rawData);
        if (data == null) {
            return INTERNAL_ERROR_RD;
        }
        ResponseData responseData = parseMessage(data);

        Log.v(TAG, responseData.toString());

        return responseData;
    }

    @Override
    protected ResponseData doInBackground(Foo... manyFoo) {
        Foo foo = Objects.requireNonNull(Objects.requireNonNull(manyFoo, "null array")[0], "null element");

        if (foo instanceof RequestData) {
            RequestData rd = (RequestData) foo;

            Log.v(TAG, "Begin processing request in BACKGROUND (RequestData)");

            return processRequest(Objects.requireNonNull(rd.encodedRequest));
        } else if (foo instanceof ResponseData) {
            ResponseData rd = (ResponseData) foo;

            Log.v(TAG, "Begin processing request in BACKGROUND (ResponseData)");

            return processResponse(rd);
        }

        throw new UnsupportedOperationException("Unknown type of Foo");
    }

    @Override
    protected void onPostExecute(Foo foo) {
        super.onPostExecute(foo);
        if (foo instanceof ResponseData) {
            display2((ResponseData) foo);
        }
    }

    public static class RequestData implements Foo {

        public final String encodedRequest;

        public RequestData(String encodedRequest) {
            this.encodedRequest = Objects.requireNonNull(encodedRequest);
        }
    }

    /** Parent of request and response data bundles. */
    public interface Foo {
    }

    public static class ResponseData implements Foo {

        /** Message to display to the user. */
        private String message;

        private NextStep nextStep;

        /** Response code from the operation. This is, at the end, delivered to the client. */
        private ResponseCode responseCode;

        /** The type of request received from the client. */
        private RequestType requestType;

        /** Necessary data to handle the request after receiving user input. */
        private Object object;

        /** Response nonce received from the client. */
        private byte[] rawNonce;

        /** The MAC used as response code for the user to enter on the client. */
        private byte[] mac;

        public ResponseData(String message, NextStep nextStep, ResponseCode responseCode,
                            RequestType requestType, Object object) {
            this.message = message == null ? "" : message;
            this.nextStep = nextStep;
            this.responseCode = responseCode;
            this.requestType = requestType;
            this.object = object;
            this.rawNonce = null;
            this.mac = null;
        }

        public ResponseData(String message, NextStep nextStep,
                            ResponseCode responseCode, RequestType requestType) {
            this(message, nextStep, responseCode, requestType, null);
        }

        public ResponseData(String message, ResponseCode responseCode, RequestType requestType) {
            this(message, null, responseCode, requestType, null);
        }

        public ResponseData(String message) {
            this(message, null, null, null, null);
        }

        public ResponseData() {
            this(null, null, null, null, null);
        }

        public String getMessage() {
            return message;
        }

        public ResponseData setMessage(String message) {
            this.message = message;
            return this;
        }

        public NextStep getNextStep() {
            return nextStep;
        }

        public ResponseData setNextStep(NextStep nextStep) {
            this.nextStep = nextStep;
            return this;
        }

        public ResponseCode getRC() {
            return responseCode;
        }

        public ResponseData setRC(ResponseCode responseCode) {
            this.responseCode = responseCode;
            return this;
        }

        public RequestType getRT() {
            return requestType;
        }

        public ResponseData setRT(RequestType requestType) {
            this.requestType = requestType;
            return this;
        }

        public Object getObject() {
            return object;
        }

        public ResponseData setObject(Object object) {
            this.object = object;
            return this;
        }

        public byte[] getNonce() {
            return rawNonce;
        }

        public ResponseData setNonce(byte[] nonce) {
            this.rawNonce = nonce;
            return this;
        }

        public byte[] getMAC() {
            return mac;
        }

        public ResponseData setMAC(byte[] mac) {
            this.mac = mac;
            return this;
        }

        @Override
        public String toString() {
            return "ResponseData {"
                    + "message: \"" + message + "\""
                    + ", nextStep: " + (nextStep == null ? "null" : nextStep.toString())
                    + ", responseCode: " + (responseCode == null ? "null" : responseCode.toString())
                    + ", requestType: " + (requestType == null ? "null" : requestType.toString())
                    + ", object: " + (object == null ? "null" : "<exists>")
                    + ", nonce: " + (rawNonce == null ? "null" : MyUtil.toHexString(rawNonce, ":"))
                    + ", mac: " + (mac == null ? "null" : MyUtil.toHexString(mac, ":"))
                    + '}';
        }
    }

    private enum RequestType {
        INIT_FIRST_P,
        AUTH,
        ADD_P,
        REMOVE_P;
    }

    /**
     * The response codes according to the protocol
     * between the client and the token.
     */
    private enum ResponseCode {

        /** All ok, success; proceed with operation. */
        SUCCESS(b(0)),

        /** Generic failure code. */
        FAILURE(b(1)),

        /** Platform has no access rights for this operation. */
        NO_PERM(b(2)),

        /** User rejects the operation. */
        NO_AUTH(b(3)),

        /** Signals intermediate operations, not yet final response for client. */
        OK_SO_FAR(b(15));

        private final byte code;

        ResponseCode(byte code) {
            this.code = code;
        }

        byte code() {
            return this.code;
        }

        // avoid cast to byte in all values
        private static byte b(int n) {
            return (byte) n;
        }

        @Override
        public String toString() {
            return String.valueOf(code);
        }
    }

    /**
     * Tracks the next step to perform during processing of an operation.
     *
     * Some steps, e.g. {@code CONCLUDE}, are generic; others are specific to an operation.
     * Specific steps have the form {@code <operation>_<next-action>}.
     */
    private enum NextStep {

        // specific:

        /** Ask the user to authorize the operation. */
        AUTH_GET_USER_INPUT,

        /** Ready to authorize the operation. */
        AUTHORIZE_OP,

        /** Ask user whether the platform should be added to the database on the Security Token. */
        ADD_P_GET_USER_INPUT,

        /** Ready to insert the platform into the database. */
        ADD_P_INSERT_DB,

        // generic:

        /** The operation is nearly complete. Compute the response MAC and then can conclude. */
        COMPUTE_MAC,

        /**
         * Ready to give feedback to the user.
         * The operation is concluded, the message is set, and the response MAC has been computed.
         */
        CONCLUDE;
    }
}
