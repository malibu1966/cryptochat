package biz.qjumper.client.cryptochat.coordinators

import android.provider.DocumentsContract
import android.view.View
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import biz.qjumper.client.cryptochat.ChatApplication
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.managers.PersistenceManager
import biz.qjumper.client.cryptochat.ui.user.login.LoginFragment
import com.google.android.material.bottomnavigation.BottomNavigationView

object RootCoordinator {
    var activeFragment: Fragment? = null

    fun start() {
        LoginCoordinator.start()
    }

    public fun registerFragment(fragment: Fragment) {
        activeFragment = fragment
    }

    public fun startMain() {
        val navView: BottomNavigationView = ChatApplication.activity!!.findViewById(R.id.nav_view)
        navView.visibility = View.VISIBLE
        when (PersistenceManager.getNavigationTag()) {
            R.id.navigation_chat -> activeFragment!!.findNavController().navigate(R.id.navigation_chat)
            R.id.navigation_contacts -> activeFragment!!.findNavController().navigate(R.id.navigation_contacts)
            R.id.navigation_settings -> activeFragment!!.findNavController().navigate(R.id.navigation_settings)
            R.id.navigation_security -> activeFragment!!.findNavController().navigate(R.id.navigation_security)
            else -> activeFragment!!.findNavController().navigate(R.id.navigation_chat)
        }
        MainCoodinator.start()
    }
}