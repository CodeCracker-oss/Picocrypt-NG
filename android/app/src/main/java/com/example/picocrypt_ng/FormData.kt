package com.example.picocrypt_ng

import android.os.Parcelable
import kotlinx.parcelize.Parcelize


@Parcelize
data class FormData(
    val selectedFilename: String,
    val comments: String,
    val passwordInput: String,
    val confirmPasswordInput: String,
    val reedSolomon: Boolean,
    val paranoid: Boolean,
    val deniability: Boolean,
    val keyfileFilenames: List<String>,
    val keyfileOrdered: Boolean
) : Parcelable {
    val isDecrypt: Boolean
        get() = selectedFilename.isNotEmpty() && selectedFilename.endsWith(".pcv")
    val isEncrypt: Boolean
        get() = selectedFilename.isNotEmpty() && !selectedFilename.endsWith(".pcv")
    val isPasswordsMatch: Boolean
        get() = passwordInput == confirmPasswordInput
    val isPasswordValid: Boolean
        get() = passwordInput.isNotEmpty() && ((isEncrypt && isPasswordsMatch) || isDecrypt)
    val isFormValid: Boolean
        get() = selectedFilename.isNotEmpty() && isPasswordValid
}