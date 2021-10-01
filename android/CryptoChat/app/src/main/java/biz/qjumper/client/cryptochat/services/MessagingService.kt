package biz.qjumper.client.cryptochat.services

import android.util.Log
import android.widget.Toast
import biz.qjumper.client.cryptochat.ChatApplication
import biz.qjumper.client.cryptochat.managers.WampManager
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage


class MessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(p0: RemoteMessage) {
        super.onMessageReceived(p0)
        //val toast = Toast.makeText(applicationContext, "Hello Javatpoint", Toast.LENGTH_SHORT)
        //toast.show()
        ChatApplication.Companion.wampManager.init(this,"client1","secret123");
        //ChatApplication.Companion.wampManager.doAddTest()
        Log.i("GHGH", "Message received")
    }

    override fun onNewToken(token: String) {
        Log.d("GHGH", "Refreshed token: $token")

        // If you want to send messages to this application instance or
        // manage this apps subscriptions on the server side, send the
        // FCM registration token to your app server.
        //sendRegistrationToServer(token)
    }
}