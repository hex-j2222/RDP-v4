package com.gotohex.rdp.data.repository

import com.gotohex.rdp.data.db.RdpProfileDao
import com.gotohex.rdp.data.model.RdpProfile
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class RdpProfileRepository @Inject constructor(
    private val dao: RdpProfileDao
) {
    fun getAllProfiles(): Flow<List<RdpProfile>> = dao.getAllProfiles()

    suspend fun getProfileById(id: String): RdpProfile? = dao.getProfileById(id)

    suspend fun saveProfile(profile: RdpProfile) = dao.insertProfile(profile)

    suspend fun updateProfile(profile: RdpProfile) = dao.updateProfile(profile)

    suspend fun deleteProfile(profile: RdpProfile) = dao.deleteProfile(profile)

    suspend fun updateLastConnected(id: String) =
        dao.updateLastConnected(id, System.currentTimeMillis())

    suspend fun updateScreenshot(id: String, path: String) =
        dao.updateScreenshot(id, path)

    suspend fun updateConnectionState(id: String, connected: Boolean) =
        dao.updateConnectionState(id, connected)
}
