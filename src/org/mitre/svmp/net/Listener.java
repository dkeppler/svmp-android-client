package org.mitre.svmp.net;

import java.nio.ByteBuffer;

public interface Listener {
    
    public void onConnect(Exception error);
    
    public void onDisconnect();
    
    public void onStringMsg(String msg);
    public void onDataMsg(ByteBuffer msg);
    
    public void onError(Exception e);

}
