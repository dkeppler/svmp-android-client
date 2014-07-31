/*
 * Copyright (c) 2014 The MITRE Corporation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this work except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.mitre.svmp.apprtc;

import android.hardware.*;
import android.hardware.SensorEvent;
import android.os.AsyncTask;
import android.os.Binder;
import android.util.Log;
import de.duenndns.ssl.MemorizingTrustManager;

import org.mitre.svmp.client.SensorHandler;
import org.mitre.svmp.performance.PerformanceTimer;
import org.mitre.svmp.services.SessionService;
import org.mitre.svmp.activities.AppRTCActivity;
import org.mitre.svmp.auth.AuthData;
import org.mitre.svmp.auth.SVMPKeyManager;
import org.mitre.svmp.auth.module.CertificateModule;
import org.mitre.svmp.client.R;
import org.mitre.svmp.common.*;
import org.mitre.svmp.protocol.SVMPProtocol;
import org.mitre.svmp.protocol.SVMPProtocol.*;
import org.mitre.svmp.protocol.SVMPProtocol.Request.RequestType;
import org.mitre.svmp.protocol.SVMPProtocol.Response.ResponseType;
import org.mitre.svmp.common.StateMachine.STATE;
import org.webrtc.MediaConstraints;

import com.google.protobuf.InvalidProtocolBufferException;
import com.koushikdutta.async.ByteBufferList;
import com.koushikdutta.async.DataEmitter;
import com.koushikdutta.async.callback.DataCallback;
import com.koushikdutta.async.http.AsyncHttpClient;
import com.koushikdutta.async.http.AsyncHttpClient.WebSocketConnectCallback;
import com.koushikdutta.async.http.AsyncSSLEngineConfigurator;
import com.koushikdutta.async.http.WebSocket;
import com.koushikdutta.async.http.WebSocket.StringCallback;

import javax.net.SocketFactory;
import javax.net.ssl.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * @author Joe Portner
 *
 * Negotiates signaling for chatting with apprtc.appspot.com "rooms".
 * Uses the client<->server specifics of the apprtc AppEngine webapp.
 *
 * Now extended to act as a Binder object between a Service and an Activity.
 *
 * To use: create an instance of this object (registering a message handler) and
 * call connectToRoom().  Once that's done call sendMessage() and wait for the
 * registered handler to be called with received messages.
 */
public class AppRTCClient extends Binder implements SensorEventListener, Constants {
    private static final String TAG = AppRTCClient.class.getName();

    // service and activity objects
    private StateMachine machine;
    private SessionService service = null;
    private AppRTCActivity activity = null;

    // These members are only read/written under sendQueue's lock.
    private BlockingQueue<SVMPProtocol.Request> sendQueue = new LinkedBlockingQueue<SVMPProtocol.Request>();
    private AppRTCSignalingParameters signalingParams;

    // common variables
    private ConnectionInfo connectionInfo;
    private DatabaseHandler dbHandler;
    private boolean init = false; // switched to 'true' when activity first binds
    private boolean proxying = false;
    private boolean bound = false;

    // performance instrumentation
    private PerformanceTimer performance;

    // client components
    private SensorHandler sensorHandler;

    // variables for networking
    private Socket svmpSocket;
    private InputStream socketIn;
    private OutputStream socketOut;
    private SocketSender sender = null;
    private SocketListener listener = null;
    
    private AsyncHttpClient ahClient;
    private Future<WebSocket> websocket;

    // STEP 0: NEW -> STARTED
    public AppRTCClient(SessionService service, StateMachine machine, ConnectionInfo connectionInfo) {
        this.service = service;
        this.machine = machine;
        machine.addObserver(service);
        this.connectionInfo = connectionInfo;

        this.dbHandler = new DatabaseHandler(service);
        this.performance = new PerformanceTimer(service, this, connectionInfo.getConnectionID());
        this.sensorHandler = new SensorHandler(service, this);

        machine.setState(STATE.STARTED, 0);
    }

    // called from activity
    public void connectToRoom(AppRTCActivity activity) {
        this.activity = activity;
        machine.addObserver(activity);
        this.bound = true;

        // we don't initialize the SocketConnector until the activity first binds; mitigates concurrency issues
        if (!init) {
            init = true;
            (new SocketConnector()).execute();
        }
        // if the state is already running, we are reconnecting
        else if (machine.getState() == STATE.RUNNING) {
            activity.onOpen();
        }
    }

    // called from activity
    public void disconnectFromRoom() {
        this.bound = false;
        machine.removeObserver(activity);
        this.activity = null;
    }

    public boolean isBound() {
        return this.activity != null;
    }

    public SessionService getService() {
        // Return this instance of SessionService so clients can call public methods
        return this.service;
    }

    public PerformanceTimer getPerformance() {
        return performance;
    }

    public AppRTCSignalingParameters getSignalingParams() {
        return signalingParams;
    }

    // called from SDPObserver
    public void changeToErrorState() {
        machine.setState(STATE.ERROR, R.string.appRTC_toast_connection_finish);
    }

    /**
     * Disconnect from the SVMP proxy channel.
     *
     * @throws IOException
     */
    public void disconnect() {
        proxying = false;

        // we're disconnecting, update the database record with the current timestamp
        dbHandler.updateLastDisconnected(connectionInfo, new Date().getTime());
        dbHandler.close();

        performance.cancel(); // stop taking performance measurements

        // clean up client components
        sensorHandler.cleanupSensors(); // stop forwarding sensor data

        // use a new thread to shut down sockets, to avoid running into a NetworkOnMainThreadException...
        Thread socketShutdown = new Thread() {
            @Override
            public void run() {
                // clean up networking objects
                if (sender != null)
                    sender.cancel(true);
                if (listener != null)
                    listener.cancel(true);
                try {
                    if (socketIn != null)
                        socketIn.close();
                } catch(IOException e) {
                    Log.e(TAG, "Exception closing InputStream: " + e.getMessage());
                }
                try {
                    if (socketOut != null)
                        socketOut.close();
                } catch(IOException e) {
                    Log.e(TAG, "Exception closing OutputStream: " + e.getMessage());
                }
                try {
                    if (svmpSocket != null && !svmpSocket.isClosed())
                        svmpSocket.close();
                } catch(IOException e) {
                    Log.e(TAG, "Exception closing Socket: " + e.getMessage());
                }
            }
        };
        socketShutdown.start();
        
    }

    private void startProxying() {
        proxying = true;

        sender = new SocketSender();
        listener = new SocketListener();

        sender.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        listener.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    /**
     * Queue a message for sending to the room's channel and send it if already
     * connected (other wise queued messages are drained when the channel is
     * eventually established).
     */
    public synchronized void sendMessage(Request msg) {
        if (proxying)
            sendQueue.add(msg);
    }

    public MediaConstraints pcConstraints() {
        return signalingParams.pcConstraints;
    }

    // STEP 1: STARTED -> CONNECTED, Connect to the SVMP server
    private class SocketConnector extends AsyncTask<Void, Void, Integer> {

        private Request authRequest;

        @Override
        protected Integer doInBackground(Void... params) {
            int returnVal = R.string.appRTC_toast_socketConnector_fail; // resID for return message
            try {
                // attempt to get any existing auth data request that's in memory (e.g. made of user input such as password)
                authRequest = AuthData.getRequest(connectionInfo);
                if (authRequest == null) {
                    // there was no auth request in memory; see if we can construct one from a session token
                    String sessionToken = dbHandler.getSessionToken(connectionInfo);
                    if (sessionToken.length() > 0)
                        authRequest = AuthData.makeRequest(connectionInfo, sessionToken);
                }

                socketConnect();
                if (svmpSocket instanceof SSLSocket) {
                    SSLSocket sslSocket = (SSLSocket) svmpSocket;
                    sslSocket.startHandshake(); // starts the handshake to verify the cert before continuing
                }
                socketOut = svmpSocket.getOutputStream();
                socketIn = svmpSocket.getInputStream();
                returnVal = 0;
            } catch (SSLHandshakeException e) {
                String msg = e.getMessage();
                if (msg.contains("SSL handshake terminated") && msg.contains("certificate unknown")) {
                    // our client certificate isn't in the server's trust store
                    Log.e(TAG, "Untrusted client certificate!");
                    returnVal = R.string.appRTC_toast_socketConnector_failUntrustedClient;
                } else if (msg.contains("java.security.cert.CertPathValidatorException")) {
                    // the server's certificate isn't in our trust store
                    Log.e(TAG, "Untrusted server certificate!");
                    returnVal = R.string.appRTC_toast_socketConnector_failUntrustedServer;
                } else if (msg.contains("alert bad certificate")) {
                    // the server expects a certificate but we didn't provide one
                    Log.e(TAG, "Server requires client certificate!");
                    returnVal = R.string.appRTC_toast_socketConnector_failClientCertRequired;
                } else {
                    Log.e(TAG, "Error during SSL handshake: " + e.getMessage());
                    returnVal = R.string.appRTC_toast_socketConnector_failSSLHandshake;
                }
            } catch (SSLException e) {
                if (e.getMessage().contains("I/O error during system call, Connection reset by peer")) {
                    // connection failed, we tried to connect using SSL but proxy's SSL is turned off
                    returnVal = R.string.appRTC_toast_socketConnector_failSSL;
                } else {
                    Log.e(TAG, "SSLException: " + e.getMessage());
                }
            } catch (Exception e) {
                Log.e(TAG, "Exception: " + e.getMessage());
                e.printStackTrace();
            }
            return returnVal;
        }

        @Override
        protected void onPostExecute(Integer result) {
            if (result == 0) {
                machine.setState(STATE.CONNECTED, R.string.appRTC_toast_socketConnector_success); // STARTED -> CONNECTED
                new SVMPAuthenticator().execute(authRequest);
            } else {
                machine.setState(STATE.ERROR, result); // STARTED -> ERROR
            }
        }

        private void socketConnect() throws IOException, KeyStoreException, NoSuchAlgorithmException,
                CertificateException, KeyManagementException, UnrecoverableKeyException {
            // determine whether we should use SSL from the EncryptionType integer
            boolean useSsl = connectionInfo.getEncryptionType() == ENCRYPTION_SSLTLS;
            // find out if we should use the MemorizingTrustManager instead of the system trust store (set in Preferences)
            boolean useMTM = Utility.getPrefBool(service,
                    R.string.preferenceKey_connection_useMTM,
                    R.string.preferenceValue_connection_useMTM);
            // determine whether we should use client certificate authentication
            boolean useCertificateAuth = API_14 &&
                    (connectionInfo.getAuthType() & CertificateModule.AUTH_MODULE_ID) == CertificateModule.AUTH_MODULE_ID;

//            SocketFactory sf;

            Log.d(TAG, "Socket connecting to " + connectionInfo.getHost() + ":" + connectionInfo.getPort());

            ahClient = AsyncHttpClient.getDefaultInstance();
            
            String proto = "ws";

            if (useSsl) {
                // set up key managers
                KeyManager[] keyManagers = null;
                // if certificate authentication is enabled, use a key manager with the provided alias
                if (useCertificateAuth) {
                    keyManagers = new KeyManager[]{new SVMPKeyManager(service, connectionInfo.getCertificateAlias())};
                }

                // set up trust managers
                TrustManager[] trustManagers = null;

                KeyStore localTrustStore = KeyStore.getInstance("BKS");
                InputStream in = service.getResources().openRawResource(R.raw.client_truststore);
                localTrustStore.load(in, TRUSTSTORE_PASSWORD.toCharArray());
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(localTrustStore);

                // 1) If "res/raw/client_truststore.bks" is not empty, use it as the pinned cert trust store (default is empty)
                // 2) Otherwise, if the "Show certificate dialog" developer preference is enabled, use that (default is disabled)
                // 3) Otherwise, use the default system trust store, consists of normal trusted Android CA certs
                if (localTrustStore.size() > 0) {
                    // this means that "res/raw/client_truststore.bks" has been replaced with a trust store that is not empty
                    // we will use that "pinned" store to check server certificate trust
                    Log.d(TAG, "socketConnect: Using static BKS trust store to check server cert trust");
                    trustManagers = trustManagerFactory.getTrustManagers();
                } else if (useMTM) {
                    // by default useMTM is false ("Show certificate dialog" in developer preferences)
                    // this creates a certificate dialog to decide what to do with untrusted certificates, instead of flat-out rejecting them
                    Log.d(TAG, "socketConnect: Static BKS trust store is empty but MTM is enabled, using MTM to check server cert trust");
                    trustManagers = MemorizingTrustManager.getInstanceList(service);
                } else {
                    Log.d(TAG, "socketConnect: Static BKS trust store is empty and MTM is disabled, using system trust store to check server cert trust");
                    // leaving trustManagers null accomplishes this
                }

                SSLContext sslcontext = SSLContext.getInstance("TLS");
                sslcontext.init(keyManagers, trustManagers, new SecureRandom());

//                SSLSocket socket = (SSLSocket) sslcontext.getSocketFactory().createSocket(connectionInfo.getHost(), connectionInfo.getPort());
//                socket.setEnabledCipherSuites(ENABLED_CIPHERS);
//                socket.setEnabledProtocols(ENABLED_PROTOCOLS);
//                svmpSocket = socket;

                ahClient.getSSLSocketMiddleware().setSSLContext(sslcontext);
                ahClient.getSSLSocketMiddleware().setTrustManagers(trustManagers);
                //ahClient.getSSLSocketMiddleware().setHostnameVerifier(hostnameVerifier);
                ahClient.getSSLSocketMiddleware().addEngineConfigurator(new AsyncSSLEngineConfigurator() {

                    @Override
                    public void configureEngine(SSLEngine engine, String host, int port) {
                        engine.setEnabledCipherSuites(ENABLED_CIPHERS);
                        engine.setEnabledProtocols(ENABLED_PROTOCOLS);
                    }
                });
                proto = proto + "s";
            }

//            } else {
//                sf = SocketFactory.getDefault();
//                svmpSocket = sf.createSocket(connectionInfo.getHost(), connectionInfo.getPort());
//            }
//            svmpSocket.setTcpNoDelay(true);

            ahClient.websocket(proto+"://"+connectionInfo.getHost()+":"+connectionInfo.getPort(), 
                    "svmp", new WebSocketConnectCallback() 
            {
                @Override
                public void onCompleted(Exception ex, WebSocket webSocket) {
                    if (ex != null) {
                        ex.printStackTrace();
                        return;
                    }
                    webSocket.send("a string");
                    webSocket.send(new byte[10]);

                    webSocket.setStringCallback(new StringCallback() {
                        public void onStringAvailable(String s) {
                            System.out.println("I got a string: " + s);
                        }
                    });

                    webSocket.setDataCallback(new DataCallback() {
                        @Override
                        public void onDataAvailable(DataEmitter emitter, ByteBufferList byteBufferList) {
                            // TODO parse the bytes into a ProtoBuf "Response"
                            try {
                                Request.parseFrom(byteBufferList.getAllByteArray());
                                // TODO and dispatch it to some handler with a big switch block
                            } catch (InvalidProtocolBufferException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            } finally {
                                // clean up
                                byteBufferList.recycle();
                            }
                        }
                    });
                }
            });
        }
    }

    // STEP 2: CONNECTED -> AUTH, Perform authentication request/response
    private class SVMPAuthenticator extends AsyncTask<Request, Void, Integer> {

        @Override
        protected Integer doInBackground(Request... request) {
            int returnVal = R.string.appRTC_toast_svmpAuthenticator_fail;

            if (svmpSocket.isConnected() && request[0] != null) {
                try {
                    // send authentication request
                    request[0].writeDelimitedTo(socketOut);

                    // get response
                    Response resp = Response.parseDelimitedFrom(socketIn);
                    if (resp != null && resp.getType() == ResponseType.AUTH) {
                        AuthResponse authResponse = resp.getAuthResponse();
                        if (authResponse.getType() == AuthResponse.AuthResponseType.AUTH_OK) {
                            // we authenticated successfully, check if we received session information
                            if (authResponse.hasSessionInfo()) {
                                SessionInfo sessionInfo = authResponse.getSessionInfo();
                                String token = sessionInfo.getToken();
                                long expires = new Date().getTime() + (1000 * sessionInfo.getMaxLength());
                                int gracePeriod = sessionInfo.getGracePeriod();
                                dbHandler.updateSessionInfo(connectionInfo, token, expires, gracePeriod);
                            }

                            returnVal = 0; // success
                        }
                        else if (authResponse.getType() == AuthResponse.AuthResponseType.NEED_PASSWORD_CHANGE)
                            returnVal = R.string.svmpActivity_toast_needPasswordChange;
                        else if (authResponse.getType() == AuthResponse.AuthResponseType.PASSWORD_CHANGE_FAIL)
                            returnVal = R.string.appRTC_toast_svmpAuthenticator_passwordChangeFail;
                        // otherwise, got an AuthResponse with a type of AUTH_FAIL
                    } else if (resp == null)
                        returnVal = R.string.appRTC_toast_svmpAuthenticator_interrupted;

                    // should be an AuthResponse with a type of AUTH_FAIL, but fail anyway if it isn't
                } catch (IOException e) {
                    // client isn't using encryption, server is
                    if (e.getMessage().equals("Protocol message contained an invalid tag (zero)."))
                        returnVal = R.string.appRTC_toast_socketConnector_failSSL;
                    else
                        Log.e(TAG, e.getMessage());
                }
            }
            return returnVal;
        }

        @Override
        protected void onPostExecute(Integer result) {
            if (result == 0) {
                machine.setState(STATE.AUTH, R.string.appRTC_toast_svmpAuthenticator_success); // CONNECTED -> AUTH
                // auth succeeded, wait for VMREADY
                (new SVMPReadyWait()).execute();
            } else {
                // authentication failed, handle appropriately
                machine.setState(STATE.ERROR, result); // CONNECTED -> ERROR
            }
        }
    }

    // STEP 3: AUTH -> READY, AsyncTask that waits for the VMREADY message from the SVMP server
    private class SVMPReadyWait extends AsyncTask<Void, Void, Boolean> {
        @Override
        protected Boolean doInBackground(Void... params) {
            // wait for VMREADY
            Response resp;
            try {
                resp = Response.parseDelimitedFrom(socketIn);
                if (resp != null && resp.getType() == ResponseType.VMREADY)
                    return true;
            } catch (IOException e) {
                Log.e(TAG, e.getMessage());
            }
            return false;
        }

        @Override
        protected void onPostExecute(Boolean result) {
            if (result) {
                machine.setState(STATE.READY, R.string.appRTC_toast_svmpReadyWait_success); // AUTH -> READY
                // auth succeeded, get room parameters
                (new VideoParameterGetter()).execute();
            } else {
                machine.setState(STATE.ERROR, R.string.appRTC_toast_svmpReadyWait_fail); // AUTH -> ERROR
            }
        }
    }

    // STEP 4: READY -> RUNNING, AsyncTask that converts an AppRTC room URL into the set of signaling parameters to use
    // with that room.
    private class VideoParameterGetter
            extends AsyncTask<Void, Void, AppRTCSignalingParameters> {

        @Override
        protected AppRTCSignalingParameters doInBackground(Void... params) {
            AppRTCSignalingParameters value = null;
            try {
                // send video info request
                Request.Builder req = Request.newBuilder();
                req.setType(RequestType.VIDEO_PARAMS);
                req.build().writeDelimitedTo(socketOut);
                
                // send timezone update too
                req.clear();
                req.setType(RequestType.TIMEZONE);
                req.setTimezoneId(TimeZone.getDefault().getID());
                req.build().writeDelimitedTo(socketOut);

                // get video info response
                Response resp = Response.parseDelimitedFrom(socketIn);

                // parse it and populate a SignalingParams
                if (resp != null && (resp.getType() == ResponseType.VIDSTREAMINFO || resp.hasVideoInfo()))
                    value = AppRTCHelper.getParametersForRoom(resp.getVideoInfo());

            } catch (Exception e) {
                Log.e(TAG, e.getMessage());
            }
            return value;
        }

        @Override
        protected void onPostExecute(AppRTCSignalingParameters params) {
            if (params != null) {
                machine.setState(STATE.RUNNING, R.string.appRTC_toast_videoParameterGetter_success); // READY -> RUNNING
                startProxying();

                signalingParams = params;
                service.onOpen();
                if (bound)
                    activity.onOpen();

                performance.start(); // start taking performance measurements
                sensorHandler.initSensors(); // start forwarding sensor data
            }
            else {
                machine.setState(STATE.ERROR, R.string.appRTC_toast_videoParameterGetter_fail); // READY -> ERROR
            }
        }
    }

    // Send loop thread for when we're in proxying mode
    private class SocketSender extends AsyncTask<Void, Void, Void> {

        @Override
        protected Void doInBackground(Void... params) {
            Log.i(TAG, "Server connection send thread starting");
            while (proxying && svmpSocket != null && svmpSocket.isConnected() && socketOut != null) {
                try {
                    // too noisy to leave enabled
                    //Log.d(TAG,"Writing message to VM...");
                    sendQueue.take().writeDelimitedTo(socketOut);
                } catch (Exception e) {
                    if (proxying) {
                        // this was an error; log this as an Error message and change state
                        machine.setState(STATE.ERROR, R.string.appRTC_toast_connection_finish);
                        Log.e(TAG, "Exception in sendMessage " + e.getMessage());
                    }
                    // otherwise, we called disconnect(), this was intentional
                }
            }
            return null;
        }
    }

    // Receive loop thread for when we're in proxying mode
    private class SocketListener extends AsyncTask<Void, Void, Void> {
        @Override
        protected Void doInBackground(Void... params) {
            try {
                Log.i(TAG, "Server connection receive thread starting");
                while (proxying && svmpSocket != null && svmpSocket.isConnected() && socketIn != null) {
                    Log.d(TAG, "Waiting for incoming message");
                    final Response data = Response.parseDelimitedFrom(socketIn);
                    Log.d(TAG, "Received incoming message object of type " + data.getType().name());

                    if (data != null) {
                        boolean consumed = service.onMessage(data);
                        if (!consumed && bound) {
                            activity.runOnUiThread(new Runnable() {
                                public void run() {
                                    activity.onMessage(data);
                                }
                            });
                        }
                    }
                }
                Log.i(TAG, "Server connection receive thread exiting");
            } catch (Exception e) {
                if (proxying) {
                    // we haven't called disconnect(), this was an error; log this as an Error message and change state
                    machine.setState(STATE.ERROR, R.string.appRTC_toast_connection_finish);
                    Log.e(TAG, "Server connection disconnected: " + e.getMessage());
                }
                else {
                    // we called disconnect(), this was intentional; log this as an Info message
                    Log.i(TAG, "Server connection disconnected.");
                }
            }
            return null;
        }
    }

    // Bridge the SensorEventListener callbacks to the SensorHandler
    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
        if (proxying)
            sensorHandler.onAccuracyChanged(sensor, accuracy);
    }

    @Override
    public void onSensorChanged(SensorEvent event) {
        if (proxying)
            sensorHandler.onSensorChanged(event);
    }
}
