package com.phoenix.client.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = PhoenixOrange,
    onPrimary = PhoenixBackground,
    secondary = PhoenixOrangeDark,
    background = PhoenixBackground,
    surface = PhoenixSurface,
    onSurface = PhoenixOnSurface,
    onBackground = PhoenixOnSurface,
)

@Composable
fun PhoenixTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content,
    )
}
