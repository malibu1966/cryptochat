package biz.qjumper.client.cryptochat

import android.os.Build
import android.os.Bundle
import com.google.android.material.bottomnavigation.BottomNavigationView
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import biz.qjumper.client.cryptochat.coordinators.RootCoordinator
import java.util.Base64
import androidx.annotation.RequiresApi
import biz.qjumper.client.cryptochat.managers.AesManager
import biz.qjumper.client.cryptochat.managers.RsaManager
import javax.crypto.SecretKey

class MainActivity : AppCompatActivity() {

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ChatApplication.activity = this
        setContentView(R.layout.activity_main)
        val navView: BottomNavigationView = findViewById(R.id.nav_view)

        val navController = findNavController(R.id.nav_host_fragment)
        // Passing each menu ID as a set of Ids because each
        // menu should be considered as top level destinations.
        val appBarConfiguration = AppBarConfiguration(setOf(
                R.id.navigation_chat, R.id.navigation_contacts, R.id.navigation_settings, R.id.navigation_security))
        setupActionBarWithNavController(navController, appBarConfiguration)
        navView.setupWithNavController(navController)

        ChatApplication.navView = navView
        ChatApplication.navController = navController
        RootCoordinator.start()
    }
}