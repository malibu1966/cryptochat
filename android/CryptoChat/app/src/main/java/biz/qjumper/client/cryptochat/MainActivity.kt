package biz.qjumper.client.cryptochat


import RSA
import RSA.Companion.decryptMessage
import RSA.Companion.encryptMessage
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

        val secretText = "www.knowledgefactory.net"
        val keyPairGenerator = RSA()
        // Generate private and public key
        val privateKey: String = Base64.getEncoder().

        encodeToString(keyPairGenerator.privateKey.encoded)
        val publicKey: String = Base64.getEncoder().

        encodeToString(keyPairGenerator.publicKey.encoded)
        println("Private Key: $privateKey")
        println("Public Key: $publicKey")
        // Encrypt secret text using public key
        val encryptedValue = encryptMessage(secretText, publicKey)
        println("Encrypted Value: $encryptedValue")
        // Decrypt
        val decryptedText = decryptMessage(encryptedValue, privateKey)
        println("Decrypted output: $decryptedText")
    }
}