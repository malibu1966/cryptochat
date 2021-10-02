package biz.qjumper.client.cryptochat.managers

import androidx.lifecycle.MutableLiveData
import biz.qjumper.client.cryptochat.ChatApplication
import biz.qjumper.client.cryptochat.Constants
import com.android.volley.*
import com.android.volley.Request.Method.POST
import com.android.volley.toolbox.JsonObjectRequest
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley
import org.json.JSONException
import org.json.JSONObject
import kotlin.collections.MutableMap as MutableMap1

object UserManager {
    val loggedIn : MutableLiveData<Constants.LoginStatus> = MutableLiveData<Constants.LoginStatus>()
    public fun login(username: String, password: String) {
        volleyPost(username, password)
    }

    fun volleyPost(username: String, password: String) {
        val postUrl = Constants.webServerUri + Constants.loginPostfix
        val requestQueue: RequestQueue = Volley.newRequestQueue(ChatApplication.activity)
        val sr: StringRequest = object : StringRequest(Method.POST, postUrl,
            Response.Listener { response ->
                val responseObj = JSONObject(response)
                println("RESPONSE:"+responseObj["result"])
                if (responseObj["result"]=="success") {
                    loggedIn.postValue(Constants.LoginStatus.LOGGED_IN)
                }
                else {
                    loggedIn.postValue(Constants.LoginStatus.LOGGED_OUT)
                }
            },
            Response.ErrorListener { error ->
                loggedIn.postValue(Constants.LoginStatus.LOGGED_OUT)
            }) {
            override fun getParams(): HashMap<String, String> {
                val params: HashMap<String, String> = HashMap()
                params["username"] = username
                params["password"] = password
                params["rsa_pubkey"] = ""
                return params
            }

        }

        requestQueue.add(sr)
    }

    public fun logout() {
        loggedIn.postValue(Constants.LoginStatus.RESET)
    }
}