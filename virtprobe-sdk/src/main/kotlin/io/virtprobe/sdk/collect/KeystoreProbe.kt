// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import io.virtprobe.core.model.KeystoreSnapshot
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * 用 Android Keystore 生成一把仅供探针使用的密钥，读取它是否在安全硬件里，
 * 并尽量解析证明扩展中的 RootOfTrust（可信根）。失败只记录原因。
 */
internal object KeystoreProbe {
    private const val AES_ALIAS = "virtprobe.hw"
    private const val EC_ALIAS = "virtprobe.attest"
    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    fun collect(): KeystoreSnapshot {
        return try {
            val keystore = KeyStore.getInstance("AndroidKeyStore")
            keystore.load(null)
            ensureAes(keystore)
            val hardware = insideHardware(keystore)
            val attestation = attest(keystore)
            KeystoreSnapshot(
                available = true,
                insideSecureHardware = hardware,
                attestationPresent = attestation.present,
                attestationSecurityLevel = attestation.level,
                verifiedBootState = attestation.boot,
                deviceLocked = attestation.locked,
                error = attestation.error,
            )
        } catch (t: Throwable) {
            KeystoreSnapshot(available = false, error = "${t.javaClass.simpleName}: ${t.message.orEmpty()}")
        }
    }

    private fun ensureAes(keystore: KeyStore) {
        if (keystore.containsAlias(AES_ALIAS)) return
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            AES_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        generator.generateKey()
    }

    private fun insideHardware(keystore: KeyStore): Boolean? {
        val key = keystore.getKey(AES_ALIAS, null) as? SecretKey ?: return null
        val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return info.isInsideSecureHardware
    }

    private fun attest(keystore: KeyStore): AttestationBits {
        return try {
            if (!keystore.containsAlias(EC_ALIAS)) {
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(EC_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge("virtprobe".toByteArray())
                    .build()
                generator.initialize(spec)
                generator.generateKeyPair()
            }
            val leaf = keystore.getCertificateChain(EC_ALIAS)?.firstOrNull() as? X509Certificate
                ?: return AttestationBits(present = false, error = "没有证明证书链")
            val extension = leaf.getExtensionValue(ATTESTATION_OID)
                ?: return AttestationBits(present = false, error = "证书没有密钥证明扩展")
            AttestationParser.parse(extension)
        } catch (t: Throwable) {
            AttestationBits(present = false, error = "${t.javaClass.simpleName}: ${t.message.orEmpty()}")
        }
    }
}

internal data class AttestationBits(
    val present: Boolean,
    val level: String? = null,
    val boot: String? = null,
    val locked: Boolean? = null,
    val error: String? = null,
)

/**
 * 只解析 KeyDescription 开头的安全级别，以及 teeEnforced 授权列表里的 tag 704（RootOfTrust）。
 * 解析不了就留下 error，不把半截结果当成「验证通过」。
 */
internal object AttestationParser {
    fun parse(extension: ByteArray): AttestationBits {
        val body = unwrapOctets(extension)
        val cursor = DerCursor(body)
        cursor.expectSequence()
        cursor.readInteger()
        val attestationLevel = cursor.readEnumerated()
        cursor.readInteger()
        val keymasterLevel = cursor.readEnumerated()
        cursor.skip()
        cursor.skip()
        cursor.skip()
        val tee = cursor.readSequenceBytes()
        val root = findRoot(tee)
        return AttestationBits(
            present = true,
            level = securityLevel(maxOf(attestationLevel, keymasterLevel)),
            boot = root?.first,
            locked = root?.second,
        )
    }

    private fun unwrapOctets(bytes: ByteArray): ByteArray {
        var current = bytes
        repeat(2) {
            if (current.isEmpty() || (current[0].toInt() and 0x1f) != 4) return current
            current = DerCursor(current).readOctet()
        }
        return current
    }

    private fun findRoot(tee: ByteArray): Pair<String, Boolean>? {
        val cursor = DerCursor(tee)
        while (!cursor.exhausted()) {
            val tag = cursor.readTag()
            val length = cursor.readLength()
            val content = cursor.take(length)
            if (tag.klass == 2 && tag.number == 704) {
                return readRoot(content)
            }
        }
        return null
    }

    private fun readRoot(content: ByteArray): Pair<String, Boolean>? {
        val cursor = DerCursor(content)
        if (!cursor.exhausted() && cursor.peekUniversal(0x10)) cursor.expectSequence()
        cursor.skip()
        val locked = cursor.readBoolean()
        val state = cursor.readEnumerated()
        return bootState(state) to locked
    }

    private fun securityLevel(value: Int): String = when (value) {
        0 -> "Software"
        1 -> "TrustedEnvironment"
        2 -> "StrongBox"
        else -> "Unknown($value)"
    }

    private fun bootState(value: Int): String = when (value) {
        0 -> "Verified"
        1 -> "SelfSigned"
        2 -> "Unverified"
        3 -> "Failed"
        else -> "Unknown($value)"
    }
}

internal class DerCursor(private val data: ByteArray) {
    private var index = 0

    fun exhausted(): Boolean = index >= data.size

    fun expectSequence() {
        val tag = readTag()
        if (tag.number != 0x10 || tag.klass != 0) throw IllegalArgumentException("不是 SEQUENCE")
        readLength()
    }

    fun readSequenceBytes(): ByteArray {
        val tag = readTag()
        if (tag.number != 0x10 || tag.klass != 0) throw IllegalArgumentException("不是 SEQUENCE")
        return take(readLength())
    }

    fun readOctet(): ByteArray {
        val tag = readTag()
        if (tag.number != 4 || tag.klass != 0) throw IllegalArgumentException("不是 OCTET STRING")
        return take(readLength())
    }

    fun readInteger(): Int = readUnsigned(0x02)

    fun readEnumerated(): Int = readUnsigned(0x0a)

    fun readBoolean(): Boolean {
        val tag = readTag()
        if (tag.number != 1 || tag.klass != 0) throw IllegalArgumentException("不是 BOOLEAN")
        val bytes = take(readLength())
        return bytes.isNotEmpty() && bytes[0].toInt() != 0
    }

    fun skip() {
        readTag()
        val length = readLength()
        index += length
    }

    fun peekUniversal(number: Int): Boolean {
        if (index >= data.size) return false
        val first = data[index].toInt() and 0xff
        return first and 0xe0 == 0 && first and 0x1f == number
    }

    fun readTag(): DerTag {
        if (index >= data.size) throw IllegalArgumentException("DER 越界")
        val first = data[index++].toInt() and 0xff
        var number = first and 0x1f
        if (number == 0x1f) {
            number = 0
            while (index < data.size) {
                val byte = data[index++].toInt() and 0xff
                number = (number shl 7) or (byte and 0x7f)
                if (byte and 0x80 == 0) break
            }
        }
        return DerTag(klass = first shr 6, constructed = first and 0x20 != 0, number = number)
    }

    fun readLength(): Int {
        if (index >= data.size) throw IllegalArgumentException("DER 长度越界")
        val first = data[index++].toInt() and 0xff
        if (first and 0x80 == 0) return first
        val count = first and 0x7f
        if (count == 0 || count > 4) throw IllegalArgumentException("不支持的 DER 长度")
        var length = 0
        repeat(count) {
            length = (length shl 8) or (data[index++].toInt() and 0xff)
        }
        return length
    }

    fun take(length: Int): ByteArray {
        if (length < 0 || index + length > data.size) throw IllegalArgumentException("DER 内容越界")
        val slice = data.copyOfRange(index, index + length)
        index += length
        return slice
    }

    private fun readUnsigned(expected: Int): Int {
        val tag = readTag()
        if (tag.number != expected || tag.klass != 0) throw IllegalArgumentException("DER 类型不符")
        val bytes = take(readLength())
        var value = 0
        for (byte in bytes) value = (value shl 8) or (byte.toInt() and 0xff)
        return value
    }
}

internal data class DerTag(val klass: Int, val constructed: Boolean, val number: Int)
