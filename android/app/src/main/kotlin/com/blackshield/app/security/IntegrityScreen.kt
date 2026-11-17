package com.blackshield.app.security

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.blackshield.app.R
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.IconTile
import com.blackshield.core.designsystem.component.PrimaryActionButton
import com.blackshield.core.designsystem.theme.BsTheme

/** Shown instead of the app when [AppIntegrity] finds a problem. There is no way past it. */
@Composable
fun IntegrityScreen() {
    val context = LocalContext.current
    Surface(color = MaterialTheme.colorScheme.background, modifier = Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp).testTag("integrity"),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            IconTile(DsR.drawable.bs_ic_report, BsTheme.status.danger, size = 72.dp)
            Text(
                stringResource(R.string.integrity_title),
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.semantics { heading() }
            )
            Text(
                stringResource(R.string.integrity_body),
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            PrimaryActionButton(
                text = stringResource(R.string.integrity_uninstall),
                onClick = {
                    context.startActivity(
                        Intent(Intent.ACTION_DELETE, Uri.fromParts("package", context.packageName, null))
                    )
                }
            )
        }
    }
}
