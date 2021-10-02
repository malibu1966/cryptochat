package biz.qjumper.client.cryptochat

import android.app.Application
import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.NavController
import com.google.android.material.bottomnavigation.BottomNavigationView

object ChatApplication : Application() {
    public var navController: NavController? = null
    public var navView: BottomNavigationView? = null
    public var activity: AppCompatActivity? = null
}
