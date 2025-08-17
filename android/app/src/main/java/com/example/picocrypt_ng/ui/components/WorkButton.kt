package com.example.picocrypt_ng.ui.components


import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.example.picocrypt_ng.FormData


@Composable
fun WorkButton(formData: FormData) {
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    var showDialog by rememberSaveable { mutableStateOf(false) }
    val text = if (formData.isEncrypt) "Encrypt File" else "Decrypt File"
    Button(
        onClick = { showDialog = true },
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
        enabled = formData.isFormValid
    ) {
        Text(text)
    }
    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text(text) },
            text = { Text(text = "This is just a demo - actual encryption not supported yet") },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text("Confirm")
                }
            },
            dismissButton = {}
        )
    }
}