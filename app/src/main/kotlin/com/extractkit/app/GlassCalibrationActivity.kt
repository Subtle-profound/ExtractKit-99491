package com.extractkit.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import androidx.lifecycle.viewmodel.compose.viewModel

class GlassCalibrationActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EkTheme.load(this)
        setContent {
            val vm: CalibrationModel = viewModel()
            val backdrop = rememberLayerBackdrop()
            // 夜里进来时把状态栏/导航栏图标也反色
            val dark = EkTheme.dark
            LaunchedEffect(dark) {
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    val bars = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                        android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
                    window.insetsController?.setSystemBarsAppearance(if (dark) 0 else bars, bars)
                }
            }
            Box(Modifier.fillMaxSize()) {
                VividBackdropLayer(backdrop)
            NightStars()          // 与首页同一套渐变 + 半模糊
                CalibrationRoute(vm, backdrop)
            }
        }
    }

    @Composable
    private fun CalibrationRoute(vm: CalibrationModel, backdrop: com.kyant.backdrop.backdrops.LayerBackdrop) {
        val pickBoot = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) vm.analyze(contentResolver, uri)
        }
        val pickProfile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) vm.importProfile(contentResolver, uri)
        }

        val intent = vm.shareIntent
        LaunchedEffect(intent) {
            if (intent != null) {
                runCatching { startActivity(intent) }
                vm.shareIntent = null
            }
        }

        GlassCalibrationScreen(
            backdrop = backdrop,
            model = vm,
            onBack = { finish() },
            onPick = { pickBoot.launch(arrayOf("*/*")) },
            onImport = { pickProfile.launch(arrayOf("*/*")) },
            onSave = { vm.saveProfile() },
            onShare = { vm.shareProfile() },
        )
    }
}
