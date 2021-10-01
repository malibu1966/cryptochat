package biz.qjumper.client.cryptochat

import android.app.Application
import biz.qjumper.client.cryptochat.managers.WampManager

class ChatApplication: Application() {
    companion object {
        val wampManager = WampManager.getInstance()
    }
}