package com.example.picocrypt_ng.ui.components


import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.picocrypt_ng.FormData


@Composable
fun ChooseFile(formData: FormData, onChange: (FormData) -> Unit) {
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
                        onChange(
                            formData.copy(
                                selectedFilename = c.getString(nameIndex),
                                comments = ""
                            )
                        )
                    }
                }
            }
        }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
            .clickable { filePickerLauncher.launch("*/*") },
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(formData.selectedFilename.ifEmpty { "Choose a file" })
        Icon(
            imageVector = Icons.Filled.Folder,
            contentDescription = "Choose file"
        )
    }
}

@Composable
fun Comments(formData: FormData, onChange: (FormData) -> Unit) {
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    if (formData.isDecrypt && formData.comments.isEmpty()) {
        return
    }
    var value = formData.comments
    var enabled = formData.isEncrypt
    if (formData.isEncrypt && formData.deniability) {
        value = "Disabled in deniability mode"
        enabled = false
    }
    TextField(
        value = value,
        onValueChange = { onChange(formData.copy(comments = it)) },
        label = { Text("Comments") },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
    )
}

@Composable
fun FileCard(formData: FormData, onChange: (FormData) -> Unit) {
    Card {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            ChooseFile(formData) { onChange(it) }
            Comments(formData) { onChange(it) }
        }
    }
}