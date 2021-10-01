package biz.qjumper.client.cryptochat.managers;

import android.content.Context;
import android.telecom.Call;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import biz.qjumper.client.wamp_test.models.ChallengeResponseModel;
//import biz.qjumper.client.wamp_test.models.ChatDirectoryModel;
//import biz.qjumper.client.wamp_test.models.EncryptedElementContainerModel;
//import biz.qjumper.client.wamp_test.models.EncryptedElementModel;
//import biz.qjumper.client.wamp_test.models.EventGroupSubscriptionModel;
//import biz.qjumper.client.wamp_test.models.EventModel;
//import biz.qjumper.client.wamp_test.models.OncallResponseModel;
//import biz.qjumper.client.wamp_test.models.TrustworxInternalKeyRequestModel;
//import biz.qjumper.client.wamp_test.viewmodels.EventViewModel;
import io.crossbar.autobahn.wamp.Client;
import io.crossbar.autobahn.wamp.Session;
import io.crossbar.autobahn.wamp.auth.TicketAuth;
import io.crossbar.autobahn.wamp.interfaces.IAuthenticator;
import io.crossbar.autobahn.wamp.types.CallResult;
import io.crossbar.autobahn.wamp.types.CloseDetails;
import io.crossbar.autobahn.wamp.types.EventDetails;
import io.crossbar.autobahn.wamp.types.ExitInfo;
import io.crossbar.autobahn.wamp.types.SessionDetails;
import io.crossbar.autobahn.wamp.types.Subscription;
import io.reactivex.rxjava3.annotations.NonNull;
import io.reactivex.rxjava3.core.Observable;
import io.reactivex.rxjava3.subjects.BehaviorSubject;

public class WampManager {
    private static biz.qjumper.client.cryptochat.managers.WampManager INSTANCE = null;
    Context context = null;
    biz.qjumper.client.cryptochat.managers.RsaManager rsaManager = null;
    biz.qjumper.client.cryptochat.managers.AesManager aesManager = null;
    Session session = null;
    Client client = null;
    String user = null;
    String key = null;
    String phase = "level1";
    BehaviorSubject<Integer> connectionStatusSubject = BehaviorSubject.create();
    BehaviorSubject<Object> eventGroupUpdateSubject = BehaviorSubject.create();
    BehaviorSubject<String> securityPhaseSubject;

    Object eventViewModel = null;

    public WampManager () {
        connectionStatusSubject.onNext(0);
    }

    public Session getSession() {
        return session;
    }

    public BehaviorSubject<Integer> getConnectionStatusSubject() {
        return connectionStatusSubject;
    }

    public @NonNull Observable<Integer> getConnectedObservable() {
        return connectionStatusSubject.filter(i -> i==1);
    }

    public BehaviorSubject<Object> getEncryptionGroupSubject() {
        return eventGroupUpdateSubject;
    }

    public boolean init(Context _context, String _user, String _key) {
        if (session != null && session.isConnected()) {
            connectionStatusSubject.onNext(1);
            doAddTest();
            return true;
        }
        //this.securityPhaseSubject = securityPhaseSubject;
        connectionStatusSubject.onNext(0);
        context = _context;
        rsaManager = new biz.qjumper.client.cryptochat.managers.RsaManager(context);
        aesManager = new biz.qjumper.client.cryptochat.managers.AesManager(context);
        user = _user;
        key = _key;
        Log.i("GHGH","BEFORE INIT");
        session = new Session();
        session.addOnConnectListener(this::onConnectListener);
        session.addOnJoinListener(this::onJoinListener);
        session.addOnLeaveListener(this::onLeaveListener);
        session.addOnDisconnectListener(this::onDisconnectListener);
        session.addOnReadyListener(this::onReadyListener);

        //IAuthenticator authenticator = new ChallengeResponseAuth(user, key);
        IAuthenticator authenticator = new TicketAuth(_user,_key);
        client = new Client(session, "ws://6.6.6.4:9002/ws", "realm1", authenticator);
        CompletableFuture<ExitInfo> exitFuture = client.connect();
        exitFuture.whenComplete((exitCode, throwable) -> {

        });
        Log.i("GHGH","AFTER INIT");
        return true;
    }

    public void clear() {
        session.leave();
        session = null;
        client = null;
    }

    public boolean level2init(Context _context, String _user, String _key) {
        if (session != null && session.isConnected() && phase == "level2") {
            connectionStatusSubject.onNext(1);
            return true;
        }
        phase = "level2";
        connectionStatusSubject.onNext(0);
        context = _context;
        rsaManager = new biz.qjumper.client.cryptochat.managers.RsaManager(context);
        aesManager = new biz.qjumper.client.cryptochat.managers.AesManager(context);
        user = _user;
        key = _key;
        Log.i("GHGH","BEFORE L2 WAMP CONNECTION");
        session = new Session();
        session.addOnConnectListener(this::onConnectListener);
        session.addOnJoinListener(this::onJoinListener);
        session.addOnLeaveListener(this::onLeaveListener);
        session.addOnDisconnectListener(this::onDisconnectListener);
        session.addOnReadyListener(this::onReadyListener);
        //IAuthenticator authenticator = new ChallengeResponseAuth(user, key);
        IAuthenticator authenticator = new TicketAuth(_user,_key);
        client = new Client(session, "wss://testserver.askmeit.com:9000/ws_level2_auth", "unwait", authenticator);
        CompletableFuture<ExitInfo> exitFuture = client.connect();
        exitFuture.whenComplete((exitCode, throwable) -> {

        });
        Log.i("GHGH","AFTER L2 WAMP CONNECTION");
        return true;
    }

    public static synchronized biz.qjumper.client.cryptochat.managers.WampManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new biz.qjumper.client.cryptochat.managers.WampManager();
        }
        return(INSTANCE);
    }

    public CompletableFuture<Subscription> subscribeEncryptionGroup() {
        // Subscribe to topic to receive its events.
        CompletableFuture<Subscription> subFuture = session.subscribe("biz.unwait.group_subscription_1",this::onEvent);
        subFuture.whenComplete((subscription, throwable) -> {
            if (throwable == null) {
                // We have successfully subscribed.
                System.out.println("Subscribed to topic " + subscription.topic);
            } else {
                // Something went bad.
                throwable.printStackTrace();
            }
        });
        return subFuture;
    }
    private void onEvent(List<Object> args, Map<String, Object> kwargs, EventDetails details) {
//        System.out.println(String.format("Got event: %s", args.get(0)));
//        Gson gson = new GsonBuilder().setPrettyPrinting().create();
//        EventGroupSubscriptionModel groupUpdate = gson.fromJson((String) args.get(0),
//                new TypeToken<EventGroupSubscriptionModel>() {
//                }.getType());
//        eventGroupUpdateSubject.onNext(groupUpdate);
//        if (groupUpdate.operation.equals("internal_key_update") && groupUpdate.keyTargetUid.equals(user)) {
//            byte[] aes_key = aesManager.getInternalKey();
//            if (aes_key == null) {
//                CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_b_internal_exchange_request", 1);
//                callFuture.thenAccept(callResult -> {
//                    Log.i("GHGH", String.format("Call result: %s", callResult.results.get(0)));
//                    ArrayList<TrustworxInternalKeyRequestModel> keyRequests = gson.fromJson((String) callResult.results.get(0),
//                            new TypeToken<ArrayList<TrustworxInternalKeyRequestModel>>() {
//                            }.getType());
//                    for (TrustworxInternalKeyRequestModel m : keyRequests) {
//                        if (m.receivingClientUid.equals(user) && (aes_key == null)) {
//                            Log.i("GHGH", String.format("MINE: %s", m.toString()));
//                            try {
//                                aesManager.storeInternalKey(rsaManager.decryptAES(m.response));
//                                acknowledgeKey(1);
//                            } catch (KeyStoreException e) {
//                                e.printStackTrace();
//                            } catch (UnrecoverableKeyException e) {
//                                e.printStackTrace();
//                            } catch (NoSuchAlgorithmException e) {
//                                e.printStackTrace();
//                            } catch (CertificateException e) {
//                                e.printStackTrace();
//                            } catch (IOException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
//                                e.printStackTrace();
//                            }
//                        }
//                    }
//                    if (phase == "level2") {
//                        connectionStatusSubject.onNext(1);
//                    }
//                });
//            }
//        }
    }

    private void onReadyListener(Session session) {
        Log.i("GHGH","READY");

    }

    private void onLeaveListener(Session session, CloseDetails closeDetails) {
        Log.i("GHGH","LEAVE");
    }

    private void onDisconnectListener(Session session, boolean b) {
        Log.i("GHGH","DISCONNECT");
        if (phase=="level1") {
            securityPhaseSubject.onNext("level1_disconnect");
        }
        //level2init(context,user,key);
    }

    private void onConnectListener(Session session) {
        Log.i("GHGH","CONNECT");
    }

    public void onJoinListener(Session session, SessionDetails details) {
        // Call a remote procedure.

//        if (phase == "level1") {
//            Log.i("GHGH","LEVEL 1 JOIN");
//            get_level2_challenge().thenAccept(callResult -> {
//                Log.i("GHGH", String.format("Challenge call result: %s", callResult.results.get(0)));
//            });
//        }
//
//        if (phase == "level2") {
        Log.i("GHGH","JOIN");
//
//
//            cancelPaging().thenAccept(callResult -> {
//                Log.i("GHGH","PAGING CANCELLED");
//            });
//        byte[] aesKey = aesManager.getInternalKey();
//        if (aesKey == null) {
//            requestAesKey(session);
//        }
//        subscribeEncryptionGroup();
//        //eventViewModel = new ViewModelProvider((ViewModelStoreOwner)context).get(EventViewModel.class);
//        //eventViewModel.getEvents();
//        byte[] aes_key = aesManager.getInternalKey();
//        if (aes_key == null) {
            //CompletableFuture<CallResult> callFuture = this.session.call("biz.unwait.tw_b_internal_exchange_request", 1);
            doAddTest();
//            CompletableFuture<Subscription> subFuture = this.session.subscribe("com.example.test_topic", this::subEvent);
//        subFuture.whenComplete((subscription, throwable) -> {
//            if (throwable == null) {
//                // We have successfully subscribed.
//                System.out.println("Subscribed to topic " + subscription.topic);
//            } else {
//                // Something went bad.
//                throwable.printStackTrace();
//            }
//        });
//        }
//        else {
//                connectionStatusSubject.onNext(1);
//            }
//        }
    }

    private void subEvent(List<Object> args, Map<String, Object> kwargs, EventDetails details) {
        System.out.println(String.format("Got subscription event: %s", args.get(0)));
    }

    public CompletableFuture<CallResult> doAddTest() {
        CompletableFuture<CallResult> callFuture = this.session.call("com.example.add2", 2,3);
        callFuture.thenAccept(callResult -> {
            Log.i("GHGH", String.format("Call result: %s", callResult.results.get(0)));
        });
        return callFuture;
    }

//    public CompletableFuture<CallResult> get_level2_challenge() {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_p_level2_request_challenge","PKCS1SHA1");
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            ChallengeResponseModel challengeResponse = gson.fromJson((String)callResult.results.
//                    get(0),new TypeToken<ChallengeResponseModel>(){}.getType());
//            Log.i("GHGH","RETURN"+callResult.results.get(0));
//            String decSigned = "";
//            byte[] decResult = null;
//
//            try {
//                decResult = rsaManager.decryptAES(challengeResponse.challenge);
//            } catch (KeyStoreException e) {
//                e.printStackTrace();
//            } catch (UnrecoverableKeyException e) {
//                e.printStackTrace();
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            } catch (CertificateException e) {
//                e.printStackTrace();
//            } catch (IOException e) {
//                e.printStackTrace();
//            } catch (NoSuchPaddingException e) {
//                e.printStackTrace();
//            } catch (InvalidKeyException e) {
//                e.printStackTrace();
//            } catch (BadPaddingException e) {
//                e.printStackTrace();
//            } catch (IllegalBlockSizeException e) {
//                e.printStackTrace();
//            }
//            byte[] decB64 = Base64.encode(decResult, Base64.DEFAULT);
//            String decB64str = new String(decB64);
//            Log.i("GHGH","RETURN"+decB64str);
//            send_level2_response(decB64str);
//        });
//        return callFuture;
//    }

//    public CompletableFuture<CallResult> send_level2_response(String response) {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_p_level2_challenge_response",response, "PKCSSHA256");
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            //ChallengeResponseModel challengeResponse = gson.fromJson((String)callResult.results.
//            //        get(0),new TypeToken<ChallengeResponseModel>(){}.getType());
//            Log.i("GHGH","RESPONSE RETURN"+callResult.results.get(0));
//            securityPhaseSubject.onNext("level1_complete");
//
//        });
//        return callFuture;
//    }

//    public CompletableFuture<CallResult> get_events() {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_get_events",1);
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            gson.fromJson((String)callResult.results.get(0),new TypeToken<ArrayList<EventModel>>(){}.getType());
//            //Log.i("GHGH","RETURN"+callResult.results.get(0));
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> get_event(int eventId) {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_get_event",1, eventId);
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            gson.fromJson((String)callResult.results.get(0),new TypeToken<EventModel>(){}.getType());
//            //Log.i("GHGH","RETURN"+callResult.results.get(0));
//
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> get_oncall_schedule() {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_get_oncall_rotation");
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            gson.fromJson((String)callResult.results.get(0),new TypeToken<OncallResponseModel>(){}.getType());
//            //Log.i("GHGH","RETURN"+callResult.results.get(0));
//
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> get_chat_directory() {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_get_chat_directory",1);
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            gson.fromJson((String)callResult.results.get(0),new TypeToken<ChatDirectoryModel>(){}.getType());
//            Log.i("GHGH","CHAT RETURN"+callResult.results.get(0));
//
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> register_fcm_id(String id) {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_register_fcm_id",id);
//        callFuture.thenAccept(callResult -> {
//            //Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            //gson.fromJson((String)callResult.results.get(0),new TypeToken<ChatDirectoryModel>(){}.getType());
//            Log.i("GHGH","FCM RETURN"+callResult.results.get(0));
//
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> cancelPaging() {
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.cc_f_cancel_paging");
//        callFuture.thenAccept(callResult -> {
//            //Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            //gson.fromJson((String)callResult.results.get(0),new TypeToken<ChatDirectoryModel>(){}.getType());
//            Log.i("GHGH","FCM CANCEL RETURN"+callResult.results.get(0));
//
//        });
//        return callFuture;
//    }
//
//    public CompletableFuture<CallResult> getEncryptedData(String tagName) {
//        String clientName = "event-watcher";
//        if (tagName.startsWith("inc_"))
//            clientName = "incident-finder";
//        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_b_get_element",clientName,1,tagName);
//        callFuture.thenAccept(callResult -> {
//            Gson gson = new GsonBuilder().setPrettyPrinting().create();
//            if (callResult.results.get(0).equals("null")) {
//                Log.i("GHGH","DATA: No data");
//            }
//            else {
//                EncryptedElementContainerModel encryptedElementContainer = gson.fromJson((String) callResult.results.get(0),
//                        new TypeToken<EncryptedElementContainerModel>() {
//                        }.getType());
//                EncryptedElementModel element = gson.fromJson(encryptedElementContainer.elementDataJson,
//                        new TypeToken<EncryptedElementModel>() {
//                        }.getType());
//                String data = aesManager.decrypt(element.dataBase64, element.ivBase64);
//                Log.i("GHGH", "DATA:" + data);
////                EventGroupSubscriptionModel output = new EventGroupSubscriptionModel();
////                output.operation = "encrypted_data";
////                output.encryptedData = new DecryptedElementModel();
////                output.encryptedData.tag = tagName;
////                output.encryptedData.data = data;
////                eventGroupUpdateSubject.onNext(output);
//            }
//
//        });
//        return callFuture;
//    }

    private void requestAesKey(Session session) {
        Log.i("GHGH","REQUEST AES");
        String group_id = "1";
        List<Object> args = new ArrayList<>();
        args.add(group_id);
        String rsa_pubkey = null;
        try {
            rsa_pubkey = rsaManager.getPublicKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_b_internal_report_expiry",
                "encryption_check_field",null,rsa_pubkey,1,"PKCS1_OAEP"); //Added extra param for alg
        callFuture.thenAccept(callResult -> {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            ArrayList<Object> events = gson.fromJson((String)callResult.results.get(0),new TypeToken<ArrayList<Object>>(){}.getType());
            Log.i("GHGH", String.format("Call result: %s", callResult.results.get(0)));
        });
    }

    public CompletableFuture<CallResult> acknowledgeKey(Integer encryptionGroupId) {
        CompletableFuture<CallResult> callFuture = session.call("biz.unwait.tw_b_acknowledge_key_receipt",encryptionGroupId);
        callFuture.thenAccept(callResult -> {
            //Gson gson = new GsonBuilder().setPrettyPrinting().create();
            //gson.fromJson((String)callResult.results.get(0),new TypeToken<ChatDirectoryModel>(){}.getType());
            Log.i("GHGH","KEY ACK RETURN"+callResult.results.get(0));

        });
        return callFuture;
    }
}
