package com.check;

import android.app.Application;

public class InjectApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        SignCheck.init(this);
    }
}