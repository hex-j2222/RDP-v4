package com.gotohex.rdp.di

import android.content.Context
import androidx.room.Room
import com.gotohex.rdp.data.db.HexRdpDatabase
import com.gotohex.rdp.data.db.RdpProfileDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): HexRdpDatabase =
        Room.databaseBuilder(
            context,
            HexRdpDatabase::class.java,
            HexRdpDatabase.DATABASE_NAME
        )
            .fallbackToDestructiveMigration()
            .build()

    @Provides
    @Singleton
    fun provideRdpProfileDao(db: HexRdpDatabase): RdpProfileDao = db.rdpProfileDao()
}
