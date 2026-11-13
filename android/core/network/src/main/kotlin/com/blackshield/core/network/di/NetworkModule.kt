package com.blackshield.core.network.di

import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.BlackShieldHttp
import com.blackshield.core.network.NetworkConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {
    @Provides
    @Singleton
    fun provideJson(): Json = BlackShieldHttp.json

    @Provides
    @Singleton
    fun provideNetworkConfig(): NetworkConfig = NetworkConfig.fromBuildConfig()

    @Provides
    @Singleton
    fun provideOkHttpClient(config: NetworkConfig): OkHttpClient = BlackShieldHttp.createClient(config)

    @Provides
    @Singleton
    fun provideBlackShieldApi(config: NetworkConfig, client: OkHttpClient): BlackShieldApi =
        BlackShieldHttp.createApi(config, client)
}
