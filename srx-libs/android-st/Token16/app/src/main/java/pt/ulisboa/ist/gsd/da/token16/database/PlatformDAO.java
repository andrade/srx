package pt.ulisboa.ist.gsd.da.token16.database;

import java.math.BigInteger;
import java.util.List;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

@Dao
public interface PlatformDAO {

    @Query("SELECT * FROM platform")
    List<Platform> getAll();

    @Query("SELECT * FROM platform WHERE platform_id LIKE :pid")
    Platform getByPid(BigInteger pid);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insert(Platform platform);

    @Delete
    void delete(Platform platform);
}
