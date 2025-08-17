package com.example.picocrypt_ng.ui.components


import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.example.picocrypt_ng.FormData


@Composable
fun AddKeyfile(formData: FormData, onChange: (FormData) -> Unit) {
    val context = LocalContext.current
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            val contentResolver = context.contentResolver
            val cursor = contentResolver.query(it, null, null, null, null)
            cursor?.use { c ->
                if (c.moveToFirst()) {
                    val nameIndex = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1) {
                        val keyfileFilenames = formData.keyfileFilenames + c.getString(nameIndex)
                        onChange(formData.copy(keyfileFilenames = keyfileFilenames))
                    }
                }
            }
        }
    }
    Button(
        onClick = { filePickerLauncher.launch("*/*") }, modifier = Modifier.fillMaxWidth()
    ) {
        Text("Add")
    }
}


@Composable
fun CreateKeyfile() {
    var showDialog by rememberSaveable { mutableStateOf(false) }
    Button(
        onClick = { showDialog = true }, modifier = Modifier.fillMaxWidth()
    ) {
        Text("Create")
    }
    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text(text = "Creating Keyfile") },
            text = { Text(text = "The creation of keyfiles has not been implemented yet") },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text("Confirm")
                }
            },
        )
    }
}


@Composable
fun ClearKeyfiles(formData: FormData, onChange: (FormData) -> Unit) {
    Button(
        onClick = { onChange(formData.copy(keyfileFilenames = listOf())) },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Clear")
    }
}


@Composable
fun RequireOrder(formData: FormData, onChange: (FormData) -> Unit) {
    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Require this order")
        Checkbox(
            formData.keyfileOrdered, onCheckedChange = {
                sharedPreferences.edit { putBoolean("keyfiles_ordered", it) }
                onChange(formData.copy(keyfileOrdered = it))
            }
        )
    }
}


@Composable
fun KeyfileNames(formData: FormData) {
    Text(
        text = formData.keyfileFilenames.joinToString(separator = "\n"),
        minLines = 3,
    )
}

@Composable
fun KeyfileCard(formData: FormData, onChange: (FormData) -> Unit) {
    if (!(formData.isDecrypt || formData.isEncrypt)) {
        return
    }
    ExpandableCard(title = "Keyfiles (${formData.keyfileFilenames.size})") {
        Row {
            Column(
                modifier = Modifier
                    .padding(8.dp)
                    .weight(0.4F)
            ) {
                AddKeyfile(formData) { onChange(it) }
                if (formData.isEncrypt) {
                    CreateKeyfile()
                }
                ClearKeyfiles(formData) { onChange(it) }
            }
            Column(
                modifier = Modifier
                    .padding(8.dp)
                    .weight(0.6F)
            ) {
                if (formData.isEncrypt) {
                    RequireOrder(formData) { onChange(it) }
                    HorizontalDivider()
                    Spacer(modifier = Modifier.height(8.dp))
                }
                KeyfileNames(formData)
            }
        }
    }
}