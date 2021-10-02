package biz.qjumper.client.cryptochat.managers

import biz.qjumper.client.cryptochat.ChatApplication
import biz.qjumper.client.cryptochat.Constants

object PersistenceManager {
    public fun persistNavigationTab(iconId: Int) {
        val editor = ChatApplication.activity!!.getSharedPreferences(Constants.preferencesTag, 0).edit()
        editor.putInt(Constants.activeTabPreferencesTag,iconId)
        editor.commit()
    }

    public fun getNavigationTag() : Int {
        return ChatApplication.activity!!.getSharedPreferences(Constants.preferencesTag, 0)
            .getInt(Constants.activeTabPreferencesTag, 0)
    }

    public fun persistUserName(username: String) {
        val editor = ChatApplication.activity!!.getSharedPreferences(Constants.preferencesTag, 0).edit()
        editor.putString(Constants.usernamePreferencesTag,username)
        editor.commit()
    }

    public fun getUsername() : String? {
        return ChatApplication.activity!!.getSharedPreferences(Constants.preferencesTag, 0)
            .getString(Constants.usernamePreferencesTag, "")
    }
}