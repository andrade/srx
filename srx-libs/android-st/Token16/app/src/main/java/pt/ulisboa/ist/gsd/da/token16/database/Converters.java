package pt.ulisboa.ist.gsd.da.token16.database;

import java.math.BigInteger;
import java.security.PublicKey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.room.TypeConverter;
import pt.ulisboa.ist.gsd.da.token16.CryptoManipulator;

public class Converters {

    @TypeConverter
    public static BigInteger fromLong(long input) {
        return BigInteger.valueOf(input);
    }

    @TypeConverter
    public static long pidToLong(@NonNull BigInteger pid) {
        return pid.longValue();
    }

    @TypeConverter
    @Nullable
    public static PublicKey fromString(@Nullable String s) {
        if (s == null) {
            return null;
        }
        return CryptoManipulator.PEM.fromStr(s);
    }

    @TypeConverter
    @Nullable
    public static String commPubToString(@Nullable PublicKey pub) {
        if (pub == null) {
            return null;
        }
        return CryptoManipulator.PEM.toStr(pub);
    }

    @TypeConverter
    public static Platform.Status fromInt(int n) {
        return Platform.Status.fromInteger(n);
    }

    @TypeConverter
    public static int statusToInt(@NonNull Platform.Status status) {
        return status.code();
    }
}
