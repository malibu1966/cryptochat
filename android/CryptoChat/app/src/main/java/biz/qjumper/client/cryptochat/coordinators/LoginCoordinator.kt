package biz.qjumper.client.cryptochat.coordinators

import android.view.View
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import biz.qjumper.client.cryptochat.ChatApplication
import biz.qjumper.client.cryptochat.Constants
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.databinding.FragmentLoginBinding
import biz.qjumper.client.cryptochat.managers.PersistenceManager
import biz.qjumper.client.cryptochat.ui.user.login.LoginFragment
import biz.qjumper.client.cryptochat.ui.user.login.LoginViewModel
import com.google.android.material.bottomnavigation.BottomNavigationView

object LoginCoordinator {

    var activeFragment: Fragment? = null

    public fun registerFragment(fragment: Fragment) {
        RootCoordinator.registerFragment(fragment)
        activeFragment = fragment
    }

    public fun setupView() {
        ChatApplication.navView!!.visibility = View.GONE
    }

    public fun setupCallbacks(viewModel: LoginViewModel, binding: FragmentLoginBinding) {
        if (! viewModel.loggedIn.hasActiveObservers()) {
            val loginObserver = Observer<Constants.LoginStatus> { loggedIn ->
                if (loggedIn == Constants.LoginStatus.RESET) {
                    binding.loginErrorTv.visibility = View.INVISIBLE
                } else if (loggedIn == Constants.LoginStatus.LOGGED_IN) {
                    binding.loginErrorTv.visibility = View.INVISIBLE
                    RootCoordinator.startMain()
                } else {
                    binding.loginErrorTv.visibility = View.VISIBLE
                }
            }
            viewModel.loggedIn.observe(activeFragment!!, loginObserver)
        }

        if (! binding.loginBtn.hasOnClickListeners() ) {
            binding.loginBtn.setOnClickListener {
                viewModel.username = binding.loginUsernameEt.text.toString()
                viewModel.password = binding.loginPasswordEt.text.toString()
                viewModel.login()
                PersistenceManager.persistUserName(binding.loginUsernameEt.text.toString())
            }
        }
    }

    fun start() {
    }
}