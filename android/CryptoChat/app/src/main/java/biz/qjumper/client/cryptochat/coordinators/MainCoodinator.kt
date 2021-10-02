package biz.qjumper.client.cryptochat.coordinators

import android.util.Log
import android.view.View
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import biz.qjumper.client.cryptochat.ChatApplication.navController
import biz.qjumper.client.cryptochat.ChatApplication.navView
import biz.qjumper.client.cryptochat.managers.PersistenceManager
import biz.qjumper.client.cryptochat.managers.UserManager

object MainCoodinator {
    var activeFragment : Fragment? = null

    public fun registerFragment(fragment: Fragment) {
        RootCoordinator.registerFragment(fragment)
        activeFragment = fragment
    }

    public fun setupView() {
        navView!!.visibility = View.VISIBLE
        navController!!.addOnDestinationChangedListener { controller, destination, arguments ->
            PersistenceManager.persistNavigationTab(navView!!.selectedItemId)
        }
    }

    fun start() {
    }

    fun logIn() {
    }

    fun logout() {
        UserManager.logout()
    }
}