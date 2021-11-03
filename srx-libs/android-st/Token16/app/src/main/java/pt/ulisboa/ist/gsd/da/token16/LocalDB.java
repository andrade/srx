package pt.ulisboa.ist.gsd.da.token16;

import android.content.Context;
import androidx.annotation.NonNull;

import androidx.room.Room;
import pt.ulisboa.ist.gsd.da.token16.database.Database;

class LocalDB {

    private static final String DB_NAME = "srx-platforms";

    private static Database database = null;

    static Database getInstance(@NonNull Context context) {
        if (database == null) {
            database = Room.databaseBuilder(context, Database.class, DB_NAME).build();
        }
        return database;
    }

    private LocalDB() {
    }
}
