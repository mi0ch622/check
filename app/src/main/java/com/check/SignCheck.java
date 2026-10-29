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

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// 注意：这里直接引入了隐藏类，云端会用 android-hidden-api 编译
import libcore.io.Libcore;
import libcore.io.Memory;

public class SignCheck {
    // 注入工具会自动替换这里的哈希
    private static final int EXPECTED_HASH = 0x2b3920e6;

    public static void init(Application app) {
        try {
            // 1. 基础：API 签名校验
            checkSignAPI(app);
            // 2. 进阶：Binder 签名校验（防 Java 层 Hook）
            checkSignBinder(app);
            // 3. 进阶：Inode 校验（防 IO 重定向）
            checkInode(app);
            // 4. 进阶：内存读取（防 Dex 动调）
            checkMemory(app);
        } catch (Throwable t) {
            killProcess();
        }
    }

    private static void checkSignAPI(Application app) throws Exception {
        PackageManager pm = app.getPackageManager();
        PackageInfo pi = pm.getPackageInfo(app.getPackageName(), PackageManager.GET_SIGNATURES);
        if (pi.signatures == null || pi.signatures.length == 0) {
            throw new Exception("Sign null");
        }
        if (pi.signatures[0].hashCode() != EXPECTED_HASH) {
            throw new Exception("Sign mismatch");
        }
    }

    // 使用 Binder 直接跨进程通信获取签名（绕过 PackageManager 的 Hook）
    private static void checkSignBinder(Application app) throws Exception {
        // 通过 ServiceManager 获取 package 服务的 IBinder
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);
        IBinder pmBinder = (IBinder) getService.invoke(null, "package");

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken("android.content.pm.IPackageManager");
        data.writeString(app.getPackageName());
        data.writeInt(PackageManager.GET_SIGNATURES);
        data.writeInt(0); // UserHandle.myUserId()

        pmBinder.transact(3 /* getPackageInfo */, data, reply, 0);
        reply.readException();
        
        // 利用反射调用 CREATOR，避免直接引用 PackageInfo 发生冲突
        Class<?> creatorClass = Class.forName("android.content.pm.PackageInfo$1");
        Parcelable.Creator<?> creator = (Parcelable.Creator<?>) creatorClass.newInstance();
        PackageInfo pi = (PackageInfo) reply.readTypedObject(creator);
        
        data.recycle();
        reply.recycle();

        if (pi == null || pi.signatures[0].hashCode() != EXPECTED_HASH) {
            throw new Exception("Binder Sign mismatch");
        }
    }

    // 检查 APK 的 Inode 是否被重定向（利用 libcore.io.Os）
    private static void checkInode(Application app) throws Exception {
        String apkPath = app.getPackageCodePath();
        // 获取 APK 真实文件的 inode
        long statInode = Libcore.os.stat(apkPath).st_ino;

        // 读取 /proc/self/maps 获取内存中映射的 APK inode
        FileInputStream fis = new FileInputStream("/proc/self/maps");
        byte[] buf = new byte[10240];
        int len = fis.read(buf);
        fis.close();
        String maps = new String(buf, 0, len);
        
        Matcher matcher = Pattern.compile(".*" + apkPath).matcher(maps);
        if (matcher.find()) {
            String line = matcher.group();
            String[] parts = line.split("\\s+");
            // maps 文件第 5 列是 inode
            long mapsInode = Long.parseLong(parts[4]);
            // 如果 inode 不一致，说明被 IO 重定向了
            if (mapsInode != 0 && mapsInode != statInode) {
                throw new Exception("Inode mismatch");
            }
        }
    }

    // 使用 libcore.io.Memory 直接读内存校验 DEX
    private static void checkMemory(Application app) throws Exception {
        // 简单判断：若内存读取出现异常（被反调试工具拦截），则主动退出
        byte[] buf = new byte[4];
        Memory.peekByteArray(0L, buf, 0, 4); // 故意触发，若被 Hook 会抛异常
    }

    private static void killProcess() {
        try {
            // 杀自己，不给破解者留机会
            android.os.Process.killProcess(android.os.Process.myPid());
            System.exit(0);
        } catch (Throwable ignored) {}
    }
}