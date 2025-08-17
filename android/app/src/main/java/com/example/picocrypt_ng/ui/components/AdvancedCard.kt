package com.example.picocrypt_ng.ui.components


import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.example.picocrypt_ng.FormData


@Composable
fun ExpandableCard(
    title: String, content: @Composable () -> Unit
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(text = title, modifier = Modifier.weight(1f))
                Icon(
                    imageVector = Icons.Default.ArrowDropDown,
                    contentDescription = "Expand or collapse",
                    modifier = Modifier.rotate(if (expanded) 180f else 0f)
                )
            }
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(animationSpec = tween(durationMillis = 300)),
                exit = shrinkVertically(animationSpec = tween(durationMillis = 300))
            ) {
                content()
            }
        }
    }
}


@Composable
fun LabeledCheckbox(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.clickable { onChange(!value) },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = value, onCheckedChange = { onChange(it) })
        Text(label)
    }
}


@Composable
fun AdvancedCard(formData: FormData, onChange: (FormData) -> Unit) {
    if (!formData.isEncrypt) {
        return
    }
    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val count =
        (if (formData.reedSolomon) 1 else 0) + (if (formData.deniability) 1 else 0) + (if (formData.paranoid) 1 else 0)
    ExpandableCard(title = "Advanced Settings ($count)") {
        Column(modifier = Modifier.padding(16.dp)) {
            LabeledCheckbox("Reed-Solomon", formData.reedSolomon) {
                sharedPreferences.edit { putBoolean("reed_solomon", it) }
                onChange(formData.copy(reedSolomon = it))
            }
            LabeledCheckbox("Paranoid", formData.paranoid) {
                sharedPreferences.edit { putBoolean("paranoid", it) }
                onChange(formData.copy(paranoid = it))
            }
            LabeledCheckbox("Deniability", formData.deniability) {
                sharedPreferences.edit { putBoolean("deniability", it) }
                onChange(formData.copy(deniability = it))
            }
        }
    }
}