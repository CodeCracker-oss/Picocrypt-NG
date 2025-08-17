package com.example.picocrypt_ng.ui.components


import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.semantics.contentType
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.picocrypt_ng.FormData


@Composable
fun PasswordIcon(visible: Boolean, onClick: () -> Unit) {
    val image = if (visible) Icons.Filled.Visibility else Icons.Filled.VisibilityOff
    val description = if (visible) "Hide password" else "Show password"
    IconButton(onClick = onClick) {
        Icon(imageVector = image, contentDescription = description)
    }
}


@Composable
fun Password(
    value: String,
    onChange: (String) -> Unit,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean
) {
    TextField(
        value = value,
        onValueChange = { onChange(it) },
        label = { Text("Password") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = icon,
        modifier = Modifier
            .fillMaxWidth()
            .semantics { contentType = ContentType.Password },
        supportingText = { if (isError) Text("Enter a password") })
}


@Composable
fun ConfirmPassword(
    value: String,
    onChange: (String) -> Unit,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean,
) {
    TextField(
        value = value,
        onValueChange = { onChange(it) },
        label = { Text("Confirm Password") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = icon,
        modifier = Modifier
            .fillMaxWidth()
            .semantics { contentType = ContentType.NewPassword },
        supportingText = { if (isError) Text("Passwords must match") })
}


@Composable
fun PasswordCard(
    formData: FormData,
    onChange: (FormData) -> Unit,
) {
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    var visible by rememberSaveable { mutableStateOf(false) }
    Card {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            // There is a race condition when a password manager fills out both
            // fields and triggers the callbacks at the same time. Using shared
            // variables helps reduce the chance of stale state, but is not a
            // guarantee. Consider using a ViewModel or other approach to FormData
            var passwordValue by rememberSaveable { mutableStateOf("") }
            var confirmPasswordValue by rememberSaveable { mutableStateOf("") }
            fun updatePasswords(password: String? = null, confirm: String? = null) {
                if (password != null) {
                    passwordValue = password
                }
                if (confirm != null) {
                    confirmPasswordValue = confirm
                }
                onChange(
                    formData.copy(
                        passwordInput = passwordValue, confirmPasswordInput = confirmPasswordValue
                    )
                )
            }
            Password(
                value = passwordValue,
                onChange = { updatePasswords(password = it) },
                visible = visible,
                icon = { PasswordIcon(visible) { visible = !visible } },
                isError = formData.passwordInput.isEmpty()
            )
            if (formData.isEncrypt) {
                ConfirmPassword(
                    value = confirmPasswordValue,
                    onChange = { updatePasswords(confirm = it) },
                    visible = visible,
                    isError = !formData.isPasswordsMatch,
                    icon = { PasswordIcon(visible) { visible = !visible } })
            }
        }
    }
}