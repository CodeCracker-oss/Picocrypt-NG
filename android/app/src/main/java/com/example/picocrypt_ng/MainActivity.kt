package com.example.picocrypt_ng


import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import com.example.picocrypt_ng.ui.components.AdvancedCard
import com.example.picocrypt_ng.ui.components.FileCard
import com.example.picocrypt_ng.ui.components.KeyfileCard
import com.example.picocrypt_ng.ui.components.LogoBar
import com.example.picocrypt_ng.ui.components.PasswordCard
import com.example.picocrypt_ng.ui.components.WorkButton
import com.example.picocrypt_ng.ui.theme.PicocryptNGTheme


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PicocryptNGTheme {
                Scaffold { innerPadding ->
                    Column(modifier = Modifier.padding(innerPadding)) {
                        MainLayout()
                    }
                }
            }
        }
    }
}


@Composable
fun MainLayout() {

    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    // formData is the global state passed through all necessary components
    var formData by rememberSaveable {
        mutableStateOf(
            FormData(
                "",
                "",
                "",
                "",
                reedSolomon = sharedPreferences.getBoolean("reed_solomon", false),
                paranoid = sharedPreferences.getBoolean("paranoid", false),
                deniability = sharedPreferences.getBoolean("deniability", false),
                keyfileFilenames = mutableListOf(),
                keyfileOrdered = sharedPreferences.getBoolean("keyfiles_ordered", false)
            )
        )
    }
    val scrollState = rememberScrollState()
    val focusManager = LocalFocusManager.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState)
            .imePadding()
            .clickable( // Allow tapping outside of fields to unfocus them
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = { focusManager.clearFocus() }),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LogoBar()
        FileCard(formData) { formData = it }
        Spacer(modifier = Modifier.height(24.dp))
        PasswordCard(formData) { formData = it }
        Spacer(modifier = Modifier.height(24.dp))
        AdvancedCard(formData) { formData = it }
        Spacer(modifier = Modifier.height(24.dp))
        KeyfileCard(formData) { formData = it }
        Spacer(modifier = Modifier.height(24.dp))
        WorkButton(formData)
    }
}