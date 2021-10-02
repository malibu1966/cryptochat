package biz.qjumper.client.cryptochat

class Constants {
    companion object {
        val webServerProto = "https://"
        val webServerAddress = "testserver.askmeit.com"
        val webServerPort = ""
        val webServerUri = Constants.webServerProto + Constants.webServerAddress + Constants.webServerPort
        val loginPostfix = "/rpc/registerClient"
        val noNavFragments: IntArray = intArrayOf(R.id.fragment_login)
        val preferencesTag: String = "cryptochatPrefs"
        val activeTabPreferencesTag: String = "activeTab"
        val usernamePreferencesTag: String = "username"
    }

    enum class LoginStatus {
        LOGGED_OUT, LOGGED_IN, RESET
    }
}