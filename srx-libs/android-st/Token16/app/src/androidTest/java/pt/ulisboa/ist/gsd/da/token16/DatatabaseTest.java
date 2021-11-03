package pt.ulisboa.ist.gsd.da.token16;

import android.content.Context;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.PublicKey;

import androidx.test.platform.app.InstrumentationRegistry;
import pt.ulisboa.ist.gsd.da.token16.database.Database;
import pt.ulisboa.ist.gsd.da.token16.database.Platform;

public class DatatabaseTest {

    private static Database db;

    @BeforeClass
    public static void beforeAll() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        db = LocalDB.getInstance(appContext);
    }

    @Test
    public void testInsertionPendingRP() {
        BigInteger pid = BigInteger.valueOf(12345L);
        PublicKey pub = null;
        Platform.Status status = Platform.Status.PENDING;
        Platform in = new Platform(pid, pub, status);
        db.platformDAO().insert(in);

        Platform out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(in.pid, out.pid);
        Assert.assertEquals(in.commPub, out.commPub);
        Assert.assertEquals(in.status, out.status);
    }

    @Test
    public void testInsertionAP() {
        BigInteger pid = BigInteger.valueOf(123456789L);
        PublicKey pub = CryptoManipulator.PEM.fromStr(Constants.PEM_PUB_1);
        Platform.Status status = Platform.Status.ACCEPTED_AP;
        Platform in = new Platform(pid, pub, status);
        db.platformDAO().insert(in);

        Platform out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(in.pid, out.pid);
        Assert.assertEquals(in.commPub, out.commPub);
        Assert.assertEquals(in.status, out.status);
    }

    @Test
    public void testOverwritePlatform() {
        BigInteger pid = BigInteger.valueOf(123L);
        PublicKey pub = null;
        Platform.Status status = Platform.Status.PENDING;
        Platform in = new Platform(pid, pub, status);
        db.platformDAO().insert(in);

        Platform out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(in.pid, out.pid);
        Assert.assertEquals(in.commPub, out.commPub);
        Assert.assertEquals(in.status, out.status);

        pid = BigInteger.valueOf(123L);
        pub = CryptoManipulator.PEM.fromStr(Constants.PEM_PUB_1);
        status = Platform.Status.ACCEPTED;
        in = new Platform(pid, pub, status);
        db.platformDAO().insert(in);

        out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(in.pid, out.pid);
        Assert.assertEquals(in.commPub, out.commPub);
        Assert.assertEquals(in.status, out.status);
    }

    @Test
    public void testRemovePlatform() {
        BigInteger pid = BigInteger.valueOf(567L);
        PublicKey pub = CryptoManipulator.PEM.fromStr(Constants.PEM_PUB_1);
        Platform.Status status = Platform.Status.ACCEPTED_AP;
        Platform in = new Platform(pid, pub, status);
        db.platformDAO().insert(in);

        Platform out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(in.pid, out.pid);

        db.platformDAO().delete(out);
        out = db.platformDAO().getByPid(pid);
        Assert.assertEquals(null, out);
    }

    @AfterClass
    public static void afterAll() {
        db.close();
    }
}
