package io.github.tadaka9.pqvpn;

import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;

import org.qtproject.qt.android.bindings.QtActivity;

/** Keeps Qt content clear of mandatory system bars on enforced edge-to-edge Android. */
public final class PqvpnActivity extends QtActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Window window = getWindow();
        window.setStatusBarColor(Color.rgb(10, 14, 29));
        window.setNavigationBarColor(Color.rgb(10, 14, 29));

        View content = findViewById(android.R.id.content);
        content.setOnApplyWindowInsetsListener((view, windowInsets) -> {
            android.graphics.Insets safe = windowInsets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            return windowInsets;
        });
        content.requestApplyInsets();
    }
}
