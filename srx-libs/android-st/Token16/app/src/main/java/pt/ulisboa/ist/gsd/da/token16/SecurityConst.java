package pt.ulisboa.ist.gsd.da.token16;

class SecurityConst {

    public static final String RAS_PUB_PEM
            = "-----BEGIN PUBLIC KEY-----\n"
            + "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIeFGSCnPP9gjrBEGx4LEKkHZ1hxsepAy\n"
            + "lRNwFANbZ8dyLoS7UxZBaBDC6MakhGGuT9k4ErJTVQGaEuTpgkPcsQ==\n"
            + "-----END PUBLIC KEY-----";

    public static final String KEYSTORE_TYPE = "AndroidKeyStore";

    public static final String CRYPTO_PROVIDER = "AndroidKeyStoreBCWorkaround";

    /** Algorithm for encryption. */
    public static final String ENC_ALGO = "AES";

    /** Transformation for AEAD. */
    public static final String ENC_TRANSFORMATION = "AES/GCM/NoPadding";

    public static final String SIG_ALGO = "SHA256withECDSA";
    public static final String EC_SIG_ALGO = "EC";
    public static final String EC_SIG_PROVIDER = "BC";  // others do not support EC pub keys

    /** Algorithm for computing the MAC. */
    public static final String MAC_ALGO = "HmacSHA256";
}