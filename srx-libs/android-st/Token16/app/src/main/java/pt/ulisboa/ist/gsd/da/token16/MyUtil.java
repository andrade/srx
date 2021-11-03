package pt.ulisboa.ist.gsd.da.token16;

import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

final class MyUtil {

    private MyUtil() {
    }

    public static boolean isThreadUI() {
        return Looper.myLooper() == Looper.getMainLooper();
    }

    @NonNull
    public static String toHexString(@Nullable byte[] data, String separator) {
        if (data == null) {
            return new String();
        }

        StringBuilder sb = new StringBuilder(data.length * (2 + separator.length()));

        for (byte b : data) {
            sb.append(String.format("%02x", b) + separator);
        }
        if (separator.length() != 0) {
            sb.delete(sb.length() - separator.length(), sb.length());
        }

        return sb.toString();
    }
}
