package com.check;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.system.Os;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// 引入原版所需的核心隐藏类
import libcore.io.Libcore;
import libcore.io.Memory;
import sun.misc.Unsafe;

public class SignCheck {
    // 注入工具会自动替换这里的哈希
    private static final int EXPECTED_HASH = 0x2b3920e6;

    // ==========================================
    // === 入口 1：基础保护（极速、零误报） ===
    // ==========================================
    public static void initBasic(Application app) {
        try {
            checkSignAPI(app);
            checkDebug(app);
            checkPath(app);
        } catch (Throwable t) {
            killProcess();
        }
    }

    // ==========================================
    // === 入口 2：均衡保护（防常规MT去签） ===
    // ==========================================
    public static void initStandard(Application app) {
        try {
            checkSignAPI(app);
            checkDebug(app);
            checkPath(app);
            
            checkSignV1(app);
            checkInode(app);
            checkProcessStatus();
            checkOpenFD();
        } catch (Throwable t) {
            killProcess();
        }
    }

    // ==========================================
    // === 入口 3：实验保护（防内存挂、底层调试） ===
    // ==========================================
    public static void initExperimental(Application app) {
        try {
            checkSignAPI(app);
            checkDebug(app);
            checkPath(app);
            
            checkSignV1(app);
            checkInode(app);
            checkProcessStatus();
            checkOpenFD();
            
            checkSignBinder(app);
            checkApkMemoryPermission(app);
            checkHiddenApiExemptions();
        } catch (Throwable t) {
            killProcess();
        }
    }

    // ==========================================
    // === 默认入口（兼容之前的调用） ===
    // ==========================================
    public static void init(Application app) {
        // 默认使用最严格的实验级
        initExperimental(app);
    }


    // ==========================================
    // === 以下为底层校验逻辑实现 ===
    // ==========================================

    private static void checkSignAPI(Application app) throws Exception {
        PackageManager pm = app.getPackageManager();
        PackageInfo pi = pm.getPackageInfo(app.getPackageName(), PackageManager.GET_SIGNATURES);
        if (pi.signatures == null || pi.signatures.length == 0) fail("Sign null");
        if (pi.signatures[0].hashCode() != EXPECTED_HASH) fail("Sign mismatch");
    }

    private static void checkDebug(Application app) throws Exception {
        if ((app.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) fail("Debug detected");
    }

    private static void checkPath(Application app) throws Exception {
        String path = app.getPackageCodePath();
        if (!path.startsWith("/data/app/") || !path.endsWith("/base.apk")) fail("Path invalid");
    }

    private static void checkSignBinder(Application app) throws Exception {
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);
        IBinder pmBinder = (IBinder) getService.invoke(null, "package");

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken("android.content.pm.IPackageManager");
        data.writeString(app.getPackageName());
        data.writeInt(PackageManager.GET_SIGNATURES);
        data.writeInt(0);
        pmBinder.transact(3, data, reply, 0);
        reply.readException();
        
        Class<?> creatorClass = Class.forName("android.content.pm.PackageInfo$1");
        Parcelable.Creator<?> creator = (Parcelable.Creator<?>) creatorClass.newInstance();
        PackageInfo pi = (PackageInfo) reply.readTypedObject(creator);
        data.recycle(); reply.recycle();

        if (pi == null || pi.signatures[0].hashCode() != EXPECTED_HASH) fail("Binder Sign mismatch");
    }

    private static void checkSignV1(Application app) throws Exception {
        JarFile apk = new JarFile(app.getPackageCodePath());
        JarEntry rsa = null;
        Enumeration<JarEntry> entries = apk.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (entry.getName().startsWith("META-INF/") && entry.getName().endsWith(".RSA")) {
                rsa = entry; break;
            }
        }
        if (rsa == null) fail("V1 Sign missing");

        InputStream input = apk.getInputStream(rsa);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(input);
        input.close();
        
        int v1Hash = Arrays.hashCode(cert.getEncoded());
        if (v1Hash != EXPECTED_HASH) fail("V1 Sign mismatch");
    }

    private static void checkInode(Application app) throws Exception {
        String apkPath = app.getPackageCodePath();
        long statInode = Libcore.os.stat(apkPath).st_ino;

        FileInputStream fis = new FileInputStream("/proc/self/maps");
        byte[] buf = new byte[10240];
        int len = fis.read(buf); fis.close();
        String maps = new String(buf, 0, len);
        
        Matcher matcher = Pattern.compile(".*" + apkPath).matcher(maps);
        while (matcher.find()) {
            String[] parts = matcher.group().split("\\s+");
            long mapsInode = Long.parseLong(parts[4]);
            if (mapsInode != 0 && mapsInode != statInode) fail("Inode mismatch (IO Redirect)");
        }
    }

    private static void checkProcessStatus() throws Exception {
        FileInputStream fis = new FileInputStream("/proc/self/status");
        byte[] buf = new byte[10240];
        int len = fis.read(buf); fis.close();
        String status = new String(buf, 0, len);
        
        Matcher matcher = Pattern.compile("TracerPid:\\s*(\\d+)").matcher(status);
        if (matcher.find()) {
            int tracerPid = Integer.parseInt(matcher.group(1));
            if (tracerPid != 0) fail("Debugger attached");
        }
    }

    private static void checkOpenFD() throws Exception {
        File fdDir = new File("/proc/self/fd");
        File[] files = fdDir.listFiles();
        if (files != null) {
            for (File f : files) {
                try {
                    String target = Os.readlink(f.getPath());
                    if (target != null && target.contains("memfd:")) fail("Memfd detected");
                } catch (Exception ignored) {}
            }
        }
    }

    private static void checkApkMemoryPermission(Application app) throws Exception {
        String apkPath = app.getPackageCodePath();
        FileInputStream fis = new FileInputStream("/proc/self/maps");
        byte[] buf = new byte[10240];
        int len = fis.read(buf); fis.close();
        String maps = new String(buf, 0, len);

        Matcher matcher = Pattern.compile(".*" + apkPath).matcher(maps);
        while (matcher.find()) {
            String[] parts = matcher.group().split("\\s+");
            String perm = parts[1];
            if (perm.contains("x") || perm.contains("w")) fail("APK memory permission abnormal");
            
            long start = Long.parseLong(parts[0].split("-")[0], 16);
            byte[] head = new byte[4];
            Memory.peekByteArray(start, head, 0, 4);
            if (head[0] == 0x7f && head[1] == 0x45 && head[2] == 0x4c && head[3] == 0x46) {
                fail("APK contains ELF header");
            }
        }
    }

    private static void checkHiddenApiExemptions() throws Exception {
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.O) return; 
        
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Unsafe unsafe = (Unsafe) f.get(null);
        
        Class<?> clazz = Class.forName("dalvik.system.VMRuntime");
        try {
            Method getRuntime = clazz.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object vmRuntime = getRuntime.invoke(null);
            
            Method setHiddenApiExemptions = clazz.getDeclaredMethod("setHiddenApiExemptions", String[].class);
            setHiddenApiExemptions.setAccessible(true);
        } catch (NoSuchMethodException e) {
            // 正常
        } catch (Exception e) {
             // 正常
        }
    }

    private static void fail(String reason) {
        throw new SecurityException("Integrity check failed: " + reason);
    }

    private static void killProcess() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid());
            System.exit(0);
        } catch (Throwable ignored) {}
    }
}