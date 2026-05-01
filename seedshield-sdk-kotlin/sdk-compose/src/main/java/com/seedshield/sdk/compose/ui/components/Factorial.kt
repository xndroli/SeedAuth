package com.seedshield.sdk.compose.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun SeedShieldWelcome(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = "SeedShield Compose Module",
            style = MaterialTheme.typography.h6
        )
        Text(
            text = "Hardware-attested security for Solana Seeker.",
            style = MaterialTheme.typography.body1
        )
    }
}

@Preview
@Composable
fun SeedShieldWelcomePreview() {
    MaterialTheme {
        SeedShieldWelcome()
    }
}
