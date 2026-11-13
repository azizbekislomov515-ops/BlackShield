// Numbers here are byte offsets and field sizes of the AXML structs in ResourceTypes.h,
// documented next to each read; naming every offset would not make the layout clearer.
@file:Suppress("MagicNumber")

package com.blackshield.core.scanner.analysis.manifest

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction

/** The manifest could not be parsed. The message describes where; it never contains file contents. */
class ManifestParseException(message: String) : Exception(message)

/** A typed attribute value from Android binary XML (`Res_value`). */
sealed interface AttributeValue {
    data class Text(val value: String) : AttributeValue

    data class Bool(val value: Boolean) : AttributeValue

    data class Integer(val value: Int) : AttributeValue

    /** `@type/name` reference: only resolvable with resources.arsc, which is not read. */
    data class Reference(val resourceId: Int) : AttributeValue

    data object Other : AttributeValue
}

data class XmlAttribute(
    /** Namespace URI, or null for none (e.g. the manifest's `package`). */
    val namespace: String?,
    val name: String,
    /** From the resource map; this is how the platform identifies `android:` attributes. */
    val resourceId: Int?,
    val value: AttributeValue
)

sealed interface XmlEvent {
    data class StartElement(val name: String, val attributes: List<XmlAttribute>) : XmlEvent

    data class EndElement(val name: String) : XmlEvent
}

/**
 * Reader for Android binary XML (AXML), the format of AndroidManifest.xml inside an APK.
 *
 * Every read is bounds-checked: hostile files (malware routinely ships malformed manifests to
 * break analysis tools) produce [ManifestParseException], never an IndexOutOfBounds or a huge
 * allocation. Unknown chunk types are skipped, as the platform does. Layout reference:
 * frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h.
 */
internal class BinaryXmlReader(bytes: ByteArray) {
    private val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    private var strings: StringPool? = null
    private var resourceIds = IntArray(0)

    fun events(): Sequence<XmlEvent> = sequence {
        val type = u16(0)
        val headerSize = u16(2)
        if (type != RES_XML_TYPE || headerSize < CHUNK_HEADER_SIZE) fail("not a binary XML document")
        // Some packers write a bogus total size; the platform reads up to the end of the data.
        val end = minOf(u32(4), buffer.limit().toLong()).toInt()
        var position = headerSize
        var elements = 0
        while (position + CHUNK_HEADER_SIZE <= end) {
            val chunkType = u16(position)
            val chunkHeader = u16(position + 2)
            val chunkSize = u32(position + 4)
            if (chunkHeader < CHUNK_HEADER_SIZE || chunkSize < chunkHeader || position + chunkSize > end) {
                fail("invalid chunk at offset $position")
            }
            when (chunkType) {
                RES_STRING_POOL_TYPE -> if (strings == null) strings = StringPool(buffer, position, chunkSize.toInt())

                RES_XML_RESOURCE_MAP_TYPE -> resourceIds = readResourceMap(position, chunkHeader, chunkSize.toInt())

                RES_XML_START_ELEMENT_TYPE -> {
                    if (++elements > MAX_ELEMENTS) fail("too many elements")
                    yield(startElement(position, chunkHeader))
                }

                RES_XML_END_ELEMENT_TYPE -> yield(XmlEvent.EndElement(string(u32(position + chunkHeader + 4))))

                else -> Unit // namespaces, CDATA, unknown chunks
            }
            position += chunkSize.toInt()
        }
    }

    private fun readResourceMap(position: Int, headerSize: Int, size: Int): IntArray {
        val count = (size - headerSize) / Int.SIZE_BYTES
        return IntArray(count) { buffer.getInt(position + headerSize + it * Int.SIZE_BYTES) }
    }

    private fun startElement(position: Int, headerSize: Int): XmlEvent.StartElement {
        val ext = position + headerSize
        val name = string(u32(ext + 4))
        val attributeStart = u16(ext + 8)
        val attributeSize = u16(ext + 10)
        val attributeCount = u16(ext + 12)
        if (attributeCount > 0 && attributeSize < ATTRIBUTE_SIZE) fail("invalid attribute size")
        val attributes = ArrayList<XmlAttribute>(attributeCount)
        for (i in 0 until attributeCount) {
            val at = ext + attributeStart + i * attributeSize
            val namespaceIndex = u32(at)
            val nameIndex = u32(at + 4)
            val raw = u32(at + 8)
            val dataType = u8(at + 15)
            val data = i32(at + 16)
            attributes +=
                XmlAttribute(
                    namespace = if (namespaceIndex == NO_INDEX) null else string(namespaceIndex),
                    name = string(nameIndex),
                    resourceId = if (nameIndex < resourceIds.size) resourceIds[nameIndex.toInt()] else null,
                    value = value(dataType, data, raw)
                )
        }
        return XmlEvent.StartElement(name, attributes)
    }

    private fun value(dataType: Int, data: Int, raw: Long): AttributeValue = when (dataType) {
        TYPE_STRING -> AttributeValue.Text(string(data.toLong() and MASK_32))
        TYPE_INT_BOOLEAN -> AttributeValue.Bool(data != 0)
        TYPE_INT_DEC, TYPE_INT_HEX -> AttributeValue.Integer(data)
        TYPE_REFERENCE -> AttributeValue.Reference(data)
        else -> if (raw != NO_INDEX) AttributeValue.Text(string(raw)) else AttributeValue.Other
    }

    private fun string(index: Long): String {
        if (index == NO_INDEX) return ""
        return (strings ?: fail("element before the string pool")).get(index)
    }

    private fun check(offset: Int, length: Int) {
        if (offset < 0 || offset + length > buffer.limit()) fail("read past the end at offset $offset")
    }

    private fun u8(offset: Int): Int {
        check(offset, 1)
        return buffer.get(offset).toInt() and 0xFF
    }

    private fun u16(offset: Int): Int {
        check(offset, 2)
        return buffer.getShort(offset).toInt() and 0xFFFF
    }

    private fun i32(offset: Int): Int {
        check(offset, 4)
        return buffer.getInt(offset)
    }

    private fun u32(offset: Int): Long = i32(offset).toLong() and MASK_32

    /** Lazily decoded `ResStringPool` (UTF-8 or UTF-16), cached per index. */
    private class StringPool(private val buffer: ByteBuffer, private val start: Int, private val size: Int) {
        private val count: Int
        private val utf8: Boolean
        private val stringsStart: Int
        private val cache: Array<String?>

        init {
            if (size < POOL_HEADER_SIZE) fail("string pool too small")
            val stringCount = buffer.getInt(start + 8).toLong() and MASK_32
            val flags = buffer.getInt(start + 16)
            stringsStart = buffer.getInt(start + 20)
            // Each string needs a 4-byte offset, so the count cannot exceed what the chunk holds.
            if (stringCount > (size - POOL_HEADER_SIZE) / Int.SIZE_BYTES || stringCount > MAX_STRINGS) {
                fail("invalid string count")
            }
            if (stringsStart < 0 || stringsStart > size) fail("invalid string data offset")
            count = stringCount.toInt()
            utf8 = flags and UTF8_FLAG != 0
            cache = arrayOfNulls(count)
        }

        fun get(index: Long): String {
            if (index < 0 || index >= count) fail("string index out of range")
            val i = index.toInt()
            cache[i]?.let { return it }
            val offset = buffer.getInt(start + POOL_HEADER_SIZE + i * Int.SIZE_BYTES)
            val at = start + stringsStart + offset
            if (offset < 0 || at >= start + size) fail("string offset out of range")
            return (if (utf8) utf8At(at) else utf16At(at)).also { cache[i] = it }
        }

        private fun utf16At(at: Int): String {
            var position = at
            var length = u16(position)
            position += 2
            if (length and 0x8000 != 0) {
                length = ((length and 0x7FFF) shl 16) or u16(position)
                position += 2
            }
            val bytes = length.toLong() * 2
            if (bytes > MAX_STRING_BYTES || position + bytes > start + size) fail("string exceeds the pool")
            val chars = CharArray(length) { buffer.getChar(position + it * 2) }
            return String(chars)
        }

        private fun utf8At(at: Int): String {
            var position = at
            // UTF-16 length first (ignored), then the UTF-8 byte length; each 1 or 2 bytes.
            position += if (u8(position) and 0x80 != 0) 2 else 1
            var length = u8(position)
            if (length and 0x80 != 0) {
                length = ((length and 0x7F) shl 8) or u8(position + 1)
                position += 2
            } else {
                position += 1
            }
            if (length > MAX_STRING_BYTES || position + length > start + size) fail("string exceeds the pool")
            val bytes = ByteArray(length) { buffer.get(position + it) }
            return Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        }

        private fun u8(offset: Int): Int {
            if (offset >= start + size) fail("string exceeds the pool")
            return buffer.get(offset).toInt() and 0xFF
        }

        private fun u16(offset: Int): Int {
            if (offset + 2 > start + size) fail("string exceeds the pool")
            return buffer.getShort(offset).toInt() and 0xFFFF
        }
    }

    private companion object {
        const val RES_STRING_POOL_TYPE = 0x0001
        const val RES_XML_TYPE = 0x0003
        const val RES_XML_START_ELEMENT_TYPE = 0x0102
        const val RES_XML_END_ELEMENT_TYPE = 0x0103
        const val RES_XML_RESOURCE_MAP_TYPE = 0x0180

        const val TYPE_REFERENCE = 0x01
        const val TYPE_STRING = 0x03
        const val TYPE_INT_DEC = 0x10
        const val TYPE_INT_HEX = 0x11
        const val TYPE_INT_BOOLEAN = 0x12

        const val CHUNK_HEADER_SIZE = 8
        const val POOL_HEADER_SIZE = 28
        const val ATTRIBUTE_SIZE = 20
        const val UTF8_FLAG = 1 shl 8
        const val NO_INDEX = 0xFFFFFFFFL
        const val MASK_32 = 0xFFFFFFFFL

        const val MAX_ELEMENTS = 200_000
        const val MAX_STRINGS = 1_000_000L
        const val MAX_STRING_BYTES = 64 * 1024

        fun fail(message: String): Nothing = throw ManifestParseException(message)
    }
}
