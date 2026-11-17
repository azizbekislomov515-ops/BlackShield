package com.blackshield.feature.threats.history

import android.content.res.Resources
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.HistoryFilter
import com.blackshield.core.data.repository.HistoryPeriod
import com.blackshield.core.ui.HistoryText
import com.blackshield.feature.threats.R
import java.io.OutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The exported report: what the user saved, in a stable, documented shape (docs/history-report.md). */
@Serializable
data class HistoryReport(
    val format: Int = FORMAT,
    val app: String,
    val generatedAt: String,
    val filter: ReportFilter,
    val events: List<ReportEvent>
) {
    companion object {
        const val FORMAT = 1
    }
}

@Serializable
data class ReportFilter(val period: HistoryPeriod, val verdicts: List<Verdict>, val sources: List<ScanSource>)

@Serializable
data class ReportEvent(
    val occurredAt: String,
    val kind: HistoryKind,
    val source: ScanSource,
    val verdict: Verdict,
    val subject: String,
    val target: String?,
    val riskScore: Int,
    val itemsScanned: Int,
    val threatsFound: Int,
    val durationMillis: Long,
    val detail: String
)

/** Writes the history as JSON (machine-readable) or PDF (to read or share). Local only: nothing is uploaded. */
object HistoryExport {
    private val json = Json { prettyPrint = true }

    fun report(appName: String, filter: HistoryFilter, events: List<HistoryEvent>, now: Long) = HistoryReport(
        app = appName,
        generatedAt = Instant.ofEpochMilli(now).toString(),
        filter = ReportFilter(filter.period, filter.verdicts.sorted(), filter.sources.sorted()),
        events =
            events.map {
                ReportEvent(
                    occurredAt = Instant.ofEpochMilli(it.occurredAt).toString(),
                    kind = it.kind,
                    source = it.source,
                    verdict = it.verdict,
                    subject = it.subject,
                    target = it.target,
                    riskScore = it.riskScore,
                    itemsScanned = it.itemsScanned,
                    threatsFound = it.threatsFound,
                    durationMillis = it.durationMillis,
                    detail = it.detail
                )
            }
    )

    fun writeJson(report: HistoryReport, out: OutputStream) {
        out.write(json.encodeToString(HistoryReport.serializer(), report).toByteArray(Charsets.UTF_8))
    }

    /** A plain A4 report: title, date, then one block per event. Text is wrapped and paginated. */
    fun writePdf(res: Resources, events: List<HistoryEvent>, now: Long, out: OutputStream) {
        val document = PdfDocument()
        val writer = PdfWriter(document)
        val dates = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault())
        writer.line(res.getString(R.string.report_title), TITLE_SIZE, bold = true)
        writer.line(res.getString(R.string.report_generated, dates.format(Instant.ofEpochMilli(now))), BODY_SIZE)
        writer.line(res.getQuantityString(R.plurals.report_count, events.size, events.size), BODY_SIZE)
        writer.gap()
        for (event in events) {
            writer.line(HistoryText.title(res, event), BODY_SIZE, bold = true)
            writer.line(
                res.getString(
                    R.string.report_event_meta,
                    dates.format(Instant.ofEpochMilli(event.occurredAt)),
                    HistoryText.source(res, event.source)
                ),
                SMALL_SIZE
            )
            if (event.detail.isNotBlank()) writer.line(event.detail, SMALL_SIZE)
            writer.gap()
        }
        writer.finish()
        document.writeTo(out)
        document.close()
    }

    private class PdfWriter(private val document: PdfDocument) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private var pageNumber = 0
        private var page: PdfDocument.Page = newPage()
        private var y = MARGIN

        fun line(text: String, size: Float, bold: Boolean = false) {
            paint.textSize = size
            paint.typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
            var rest = text
            while (rest.isNotEmpty()) {
                val count = paint.breakText(rest, true, PAGE_WIDTH - 2 * MARGIN, null).coerceAtLeast(1)
                // Break at the last space that fits, unless the word itself is longer than the line.
                val cut = rest.lastIndexOf(' ', count).takeIf { count < rest.length && it > 0 } ?: count
                ensureSpace(size * LINE_SPACING)
                y += size
                page.canvas.drawText(rest.substring(0, cut), MARGIN, y, paint)
                y += size * (LINE_SPACING - 1)
                rest = rest.substring(cut).trimStart()
            }
        }

        fun gap() {
            y += GAP
        }

        fun finish() = document.finishPage(page)

        private fun ensureSpace(height: Float) {
            if (y + height > PAGE_HEIGHT - MARGIN) {
                document.finishPage(page)
                page = newPage()
                y = MARGIN
            }
        }

        private fun newPage(): PdfDocument.Page = document.startPage(
            PdfDocument.PageInfo.Builder(PAGE_WIDTH.toInt(), PAGE_HEIGHT.toInt(), ++pageNumber).create()
        )
    }

    // A4 in PostScript points.
    private const val PAGE_WIDTH = 595f
    private const val PAGE_HEIGHT = 842f
    private const val MARGIN = 48f
    private const val GAP = 8f
    private const val LINE_SPACING = 1.4f
    private const val TITLE_SIZE = 20f
    private const val BODY_SIZE = 12f
    private const val SMALL_SIZE = 10f
}
