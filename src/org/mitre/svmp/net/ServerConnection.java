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
package org.mitre.svmp.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.json.JSONException;
import org.json.JSONObject;
import org.mitre.svmp.apprtc.AppRTCClient;
import org.mitre.svmp.auth.AuthData;
import org.mitre.svmp.auth.SVMPKeyManager;
import org.mitre.svmp.auth.module.CertificateModule;
import org.mitre.svmp.client.R;
import org.mitre.svmp.common.ConnectionInfo;
import org.mitre.svmp.common.Constants;
import org.mitre.svmp.common.DatabaseHandler;
import org.mitre.svmp.common.StateMachine;
import org.mitre.svmp.common.Utility;
import org.mitre.svmp.common.StateMachine.STATE;
import org.mitre.svmp.protocol.SVMPProtocol.Request;
import org.mitre.svmp.services.SessionService;

import android.annotation.SuppressLint;
import android.net.Uri;
import android.util.Log;

import com.google.PRNGFixes;
import com.google.protobuf.InvalidProtocolBufferException;
import com.koushikdutta.async.ByteBufferList;
import com.koushikdutta.async.DataEmitter;
import com.koushikdutta.async.callback.DataCallback;
import com.koushikdutta.async.future.Future;
import com.koushikdutta.async.future.FutureCallback;
import com.koushikdutta.async.http.AsyncHttpClient;
import com.koushikdutta.async.http.AsyncHttpClient.JSONObjectCallback;
import com.koushikdutta.async.http.AsyncHttpRequest;
import com.koushikdutta.async.http.AsyncHttpResponse;
import com.koushikdutta.async.http.AsyncSSLEngineConfigurator;
import com.koushikdutta.async.http.WebSocket;
import com.koushikdutta.async.http.AsyncHttpClient.WebSocketConnectCallback;
import com.koushikdutta.async.http.WebSocket.StringCallback;
import com.koushikdutta.async.http.body.AsyncHttpRequestBody;
import com.koushikdutta.async.http.body.JSONObjectBody;

import de.duenndns.ssl.MemorizingTrustManager;

public class ServerConnection {
    private static final String TAG = "SVMPServerConnection";

    // service and activity objects
    private StateMachine machine;
    private SessionService service = null;

    // common variables
    private ConnectionInfo connectionInfo;
    private DatabaseHandler dbHandler;
    private boolean proxying = false;
    private boolean useSsl;

    private SslConfig sslconfig = null;
    private AsyncHttpClient ahClient;
    private WebSocket websocket;

    private Listener listener;

    public ServerConnection(ConnectionInfo cinfo, Listener listener) 
            throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, 
                   CertificateException, IOException 
    {
        this.connectionInfo = cinfo;
        this.listener = listener;

        ahClient = AsyncHttpClient.getDefaultInstance();

        // determine whether we should use SSL from the EncryptionType integer
        useSsl = connectionInfo.getEncryptionType() == Constants.ENCRYPTION_SSLTLS;

        if (useSsl) {
            sslconfig = new SslConfig();
            ahClient.getSSLSocketMiddleware().setSSLContext(sslconfig.getContext());
            ahClient.getSSLSocketMiddleware().setTrustManagers(sslconfig.getTrustManagers());
            //ahClient.getSSLSocketMiddleware().setHostnameVerifier(hostnameVerifier);
            ahClient.getSSLSocketMiddleware().addEngineConfigurator(sslconfig.getEngineConfigurator());
        }
    }

    public void login() {
        Uri loginUri = Uri.parse("https://"+connectionInfo.getHost()+":"+connectionInfo.getPort());
        AsyncHttpRequest loginReq = new AsyncHttpRequest(loginUri, "POST");

        String sessionToken = dbHandler.getSessionToken(connectionInfo);
        if (sessionToken.length() <= 0) {
            // no existing token, have to login and get one
        }

        // attempt to get any existing auth data request that's in memory (e.g. made of user input such as password)
        authRequest = AuthData.getRequest(connectionInfo);
        if (authRequest == null) {
            // there was no auth request in memory; see if we can construct one from a session token
            String sessionToken = dbHandler.getSessionToken(connectionInfo);
            if (sessionToken.length() > 0)
                authRequest = AuthData.makeRequest(connectionInfo, sessionToken);
        }

        loginJSON = 
        loginReq.setBody(new JSONObjectBody(new JSONObject()));
        // TODO add post data for login fields

        ahClient.executeJSONObject(loginReq, new JSONObjectCallback() {
            @Override
            public void onCompleted(Exception err, AsyncHttpResponse resp, JSONObject json) {
                // json object should contain:
                //      1) Session token in JWT format
                //      2) IP/port of the svmp-server instance to connect to
                //      3) webrtc constraints
                //      4) webrtc ICE servers

                try {
                    String token = json.getString("authtoken");

                    String wsHost = json.getJSONObject("server").getString("host");
                    int wsPort = json.getJSONObject("server").getInt("port");

                    JSONObject webrtcSettings = json.getJSONObject("webrtc");

                    // TODO set those values in the various places that need them

                } catch (JSONException e) {
                    // TODO invalid login response, abort
                }
            }
        });
    }

    public void connect(String host, int port, String sessionToken) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, 
            CertificateException, IOException, InterruptedException, ExecutionException {
        Log.d(TAG, "Socket connecting to " + connectionInfo.getHost() + ":" + connectionInfo.getPort());

        String proto = useSsl ? "wss" : "ws";

        if (useSsl) {

        }

        Uri wsUri = Uri.parse(proto+"://"+host+":"+port);
        AsyncHttpRequest wsReq = new AsyncHttpRequest(wsUri, "GET");
        wsReq.addHeader("x-access-token", sessionToken);

        ahClient.websocket(wsReq, "svmp", new WebSocketConnectCallback() 
        {
            @Override
            public void onCompleted(Exception ex, WebSocket socket) {
                websocket = socket;
                if (ex != null) {
                    listener.onConnect(ex);
                    return;
                }

                socket.setStringCallback(new StringCallback() {
                    public void onStringAvailable(String s) {
                        listener.onStringMsg(s);
                    };
                });

                socket.setDataCallback(new DataCallback() {
                    @Override
                    public void onDataAvailable(DataEmitter emitter, ByteBufferList byteBufferList) {
                        listener.onDataMsg(byteBufferList.getAll());
                    }
                });
            }
        });
    }

    public void disconnect() {
        websocket.close(); // this right ???
    }

    public boolean isConnected() {
        return websocket.isOpen(); // this right ???
    }

    private class SslConfig {
        private SSLContext sslcontext;
        private TrustManager[] trustManagers = null;
        private KeyManager[] keyManagers = null;
        private AsyncSSLEngineConfigurator configurator;

        @SuppressLint("TrulyRandom")
        public SslConfig() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
                IOException, KeyManagementException {
            // find out if we should use the MemorizingTrustManager instead of the system trust store (set in Preferences)
            boolean useMTM = Utility.getPrefBool(service,
                    R.string.preferenceKey_connection_useMTM,
                    R.string.preferenceValue_connection_useMTM);

            // determine whether we should use client certificate authentication
            boolean useCertificateAuth = Constants.API_14 &&
                    (connectionInfo.getAuthType() & CertificateModule.AUTH_MODULE_ID) == CertificateModule.AUTH_MODULE_ID;

            // set up key managers
            // if certificate authentication is enabled, use a key manager with the provided alias
            if (useCertificateAuth) {
                keyManagers = new KeyManager[]{new SVMPKeyManager(service, connectionInfo.getCertificateAlias())};
            }

            // set up trust managers

            KeyStore localTrustStore = KeyStore.getInstance("BKS");
            InputStream in = service.getResources().openRawResource(R.raw.client_truststore);
            localTrustStore.load(in, Constants.TRUSTSTORE_PASSWORD.toCharArray());
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

            PRNGFixes.apply();
            sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(keyManagers, trustManagers, new SecureRandom());

            configurator = new AsyncSSLEngineConfigurator() {
                @Override
                public void configureEngine(SSLEngine engine, String host, int port) {
                    engine.setEnabledCipherSuites(Constants.ENABLED_CIPHERS);
                    engine.setEnabledProtocols(Constants.ENABLED_PROTOCOLS);
                }
            };
        }

        public SSLContext getContext() {
            return sslcontext;
        }

        public TrustManager[] getTrustManagers() {
            return trustManagers;
        }
        
        public AsyncSSLEngineConfigurator getEngineConfigurator() {
            return configurator;
        }
    }
}
