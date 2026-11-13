package com.blackshield.core.scanner.analysis.manifest

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Writes Android binary XML for tests: shapes aapt2 never produces (UTF-8 pools, renamed
 * attributes, decoys) so the parser can be checked against what packers do. Real aapt2 output is
 * covered by the .axml fixtures.
 */
class AxmlBuilder(private val utf8: Boolean = false) {
    sealed interface Value {
        data class Str(val value: String) : Value

        data class Bool(val value: Boolean) : Value

        data class Int32(val value: Int) : Value

        data class Ref(val id: Int) : Value
    }

    data class Attr(val name: String, val value: Value, val resourceId: Int? = null, val android: Boolean = true)

    class Element(val name: String, val attrs: List<Attr> = emptyList(), val children: List<Element> = emptyList())

    // A straight-line serializer of the AXML layout; splitting it would hide the byte order.
    @Suppress("CyclomaticComplexMethod")
    fun build(root: Element): ByteArray {
        // Attribute names with a resource ID come first: the resource map is index-aligned with the pool.
        val withIds = LinkedHashMap<String, Int>()
        val others = LinkedHashSet<String>()
        fun collect(element: Element) {
            element.attrs.forEach { attr -> attr.resourceId?.let { withIds.putIfAbsent(attr.name, it) } }
            element.children.forEach(::collect)
        }
        collect(root)
        fun collectStrings(element: Element) {
            others += element.name
            element.attrs.forEach { attr ->
                if (attr.resourceId == null) others += attr.name
                (attr.value as? Value.Str)?.let { others += it.value }
            }
            element.children.forEach(::collectStrings)
        }
        others += ANDROID_NS
        others += "android"
        collectStrings(root)
        // Same name string may carry a resource ID in one place and none in another: keep both slots.
        val pool = withIds.keys.toList() + others.toList()
        val index = { s: String -> pool.indexOf(s) }
        val idIndex = { name: String -> withIds.keys.indexOf(name) }
        val plainIndex = { name: String -> withIds.size + others.indexOf(name) }

        val body = ByteArrayOutputStream()
        body.write(stringPool(pool))
        body.write(chunk(0x0180, 8, withIds.values.flatMap { le32(it).toList() }.toByteArray()))
        body.write(chunk(0x0100, 16, le32(-1) + le32(-1) + le32(index("android")) + le32(index(ANDROID_NS))))
        fun write(element: Element) {
            val attrs = ByteArrayOutputStream()
            element.attrs.forEach { attr ->
                val nameIndex = if (attr.resourceId != null) idIndex(attr.name) else plainIndex(attr.name)
                val ns = if (attr.android) index(ANDROID_NS) else -1
                val (type, data, raw) =
                    when (val v = attr.value) {
                        is Value.Str -> Triple(0x03, index(v.value), index(v.value))
                        is Value.Bool -> Triple(0x12, if (v.value) -1 else 0, -1)
                        is Value.Int32 -> Triple(0x10, v.value, -1)
                        is Value.Ref -> Triple(0x01, v.id, -1)
                    }
                attrs.write(
                    le32(ns) + le32(nameIndex) + le32(raw) + le16(8) + byteArrayOf(0, type.toByte()) + le32(data)
                )
            }
            val ext = le32(-1) + le32(plainIndex(element.name)) + le16(20) + le16(20) + le16(element.attrs.size) +
                le16(0) + le16(0) + le16(0)
            body.write(chunk(0x0102, 16, le32(1) + le32(-1) + ext + attrs.toByteArray()))
            element.children.forEach(::write)
            body.write(chunk(0x0103, 16, le32(1) + le32(-1) + le32(-1) + le32(plainIndex(element.name))))
        }
        write(root)
        body.write(chunk(0x0101, 16, le32(1) + le32(-1) + le32(index("android")) + le32(index(ANDROID_NS))))
        return chunk(0x0003, 8, body.toByteArray())
    }

    private fun stringPool(strings: List<String>): ByteArray {
        val data = ByteArrayOutputStream()
        val offsets = strings.map { s ->
            val offset = data.size()
            if (utf8) {
                val bytes = s.toByteArray(Charsets.UTF_8)
                data.write(length8(s.length))
                data.write(length8(bytes.size))
                data.write(bytes)
                data.write(0)
            } else {
                data.write(length16(s.length))
                s.forEach { data.write(le16(it.code)) }
                data.write(le16(0))
            }
            offset
        }
        while (data.size() % 4 != 0) data.write(0)
        val headerAndOffsets = 28 + 4 * strings.size
        val fields = le32(strings.size) + le32(0) + le32(if (utf8) 1 shl 8 else 0) + le32(headerAndOffsets) + le32(0)
        return chunk(0x0001, 28, fields + offsets.flatMap { le32(it).toList() }.toByteArray() + data.toByteArray())
    }

    private fun length8(n: Int): ByteArray =
        if (n > 0x7F) byteArrayOf((0x80 or (n shr 8)).toByte(), (n and 0xFF).toByte()) else byteArrayOf(n.toByte())

    private fun length16(n: Int): ByteArray = if (n >
        0x7FFF
    ) {
        le16(0x8000 or (n shr 16)) + le16(n and 0xFFFF)
    } else {
        le16(n)
    }

    private fun chunk(type: Int, headerSize: Int, rest: ByteArray): ByteArray =
        le16(type) + le16(headerSize) + le32(8 + rest.size) + rest

    companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

        fun le16(v: Int): ByteArray =
            ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array()

        fun le32(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
    }
}
