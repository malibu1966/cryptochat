package biz.qjumper.client.cryptochat.ui.user.login

import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import biz.qjumper.client.cryptochat.Constants
import biz.qjumper.client.cryptochat.managers.UserManager

class LoginViewModel : ViewModel() {
    // TODO: Implement the ViewModel
    var username: String? = null
    var password: String? = null
    val loggedIn : MutableLiveData<Constants.LoginStatus> = UserManager.loggedIn

    public fun login() {
        UserManager.login(username!!, password!!)
    }
}