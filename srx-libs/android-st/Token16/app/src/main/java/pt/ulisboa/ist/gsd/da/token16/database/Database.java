package pt.ulisboa.ist.gsd.da.token16.database;

import androidx.room.RoomDatabase;

@androidx.room.Database(entities = {Platform.class}, version = 1, exportSchema = false)
@androidx.room.TypeConverters({Converters.class})
public abstract class Database extends RoomDatabase {

    public abstract PlatformDAO platformDAO();
}
