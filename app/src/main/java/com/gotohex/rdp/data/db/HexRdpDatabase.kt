package com.gotohex.rdp.data.db

import androidx.room.*
import com.gotohex.rdp.data.model.RdpProfile
import kotlinx.coroutines.flow.Flow

@Dao
interface RdpProfileDao {
    @Query("SELECT * FROM rdp_profiles ORDER BY sortOrder ASC, createdAt DESC")
    fun getAllProfiles(): Flow<List<RdpProfile>>

    @Query("SELECT * FROM rdp_profiles WHERE id = :id")
    suspend fun getProfileById(id: String): RdpProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProfile(profile: RdpProfile)

    @Update
    suspend fun updateProfile(profile: RdpProfile)

    @Delete
    suspend fun deleteProfile(profile: RdpProfile)

    @Query("UPDATE rdp_profiles SET lastConnected = :timestamp WHERE id = :id")
    suspend fun updateLastConnected(id: String, timestamp: Long)

    @Query("UPDATE rdp_profiles SET lastScreenshotPath = :path WHERE id = :id")
    suspend fun updateScreenshot(id: String, path: String)

    @Query("UPDATE rdp_profiles SET isConnected = :connected WHERE id = :id")
    suspend fun updateConnectionState(id: String, connected: Boolean)
}

@Database(
    entities = [RdpProfile::class],
    version = 1,
    exportSchema = false
)
abstract class HexRdpDatabase : RoomDatabase() {
    abstract fun rdpProfileDao(): RdpProfileDao

    companion object {
        const val DATABASE_NAME = "hex_rdp_database"
    }
}
