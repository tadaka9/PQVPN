package io.github.tadaka9.pqvpn;

import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;

import org.qtproject.qt.android.bindings.QtActivity;

/** Keeps Qt content clear of mandatory system bars on enforced edge-to-edge Android. */
public final class PqvpnActivity extends QtActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Window window = getWindow();
        window.setStatusBarColor(Color.rgb(10, 14, 29));
        window.setNavigationBarColor(Color.rgb(10, 14, 29));
        window.getDecorView().setBackgroundColor(Color.rgb(10, 14, 29));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.setStatusBarContrastEnforced(false);
            window.setNavigationBarContrastEnforced(false);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController controller = window.getInsetsController();
            if (controller != null) {
                controller.setSystemBarsAppearance(0,
                        WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
            }
        }

        View content = findViewById(android.R.id.content);
        content.setBackgroundColor(Color.rgb(10, 14, 29));
        content.setOnApplyWindowInsetsListener((view, windowInsets) -> {
            android.graphics.Insets safe = windowInsets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            return windowInsets;
        });
        content.requestApplyInsets();
    }
}
