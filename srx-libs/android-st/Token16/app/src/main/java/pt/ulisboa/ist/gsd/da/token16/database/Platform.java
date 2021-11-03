package pt.ulisboa.ist.gsd.da.token16.database;

import java.math.BigInteger;
import java.security.PublicKey;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity
public class Platform {

    @PrimaryKey
    @ColumnInfo(name = "platform_id")
    public BigInteger pid;

    @ColumnInfo(name = "communication_public_key")
    public PublicKey commPub;

    @ColumnInfo(name = "platform_status")
    public Status status;

    public Platform() {
    }

    public Platform(BigInteger pid, PublicKey pub, Status status) {
        this.pid = pid;
        this.commPub = pub;
        this.status = status;
    }

    @Override
    public String toString() {
        return String.format("Platform {pid=%016x, commPub=<?>, status=%s}", pid, status);
    }

    public enum Status {
        ACCEPTED(2),
        PENDING(3);

        private final int code;

        Status(int code) {
            this.code = code;
        }

        public int code() {
            return this.code;
        }

        public static Status fromInteger(int n) {
            for (Status e : Status.values()) {
                if (e.code == n) {
                    return e;
                }
            }
            return null;
        }
    }
}
