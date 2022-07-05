package com.shza.android_keystore

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.shza.android_keystore.databinding.ActivityMainBinding
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {
    lateinit var encryptedPairData: Pair<ByteArray, ByteArray>
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
        getKeyGenerator()

        binding.encryptBtn.setOnClickListener {
            binding.decryptedText.text = encryptWithKeyStore(binding.inputText.text.toString())
        }

        binding.decryptBtn.setOnClickListener {
            val iv = encryptedPairData.first
            val encryptedData = encryptedPairData.second
            binding.decryptedText.text = decryptData(iv, encryptedData)
        }

    }


    private fun encryptWithKeyStore(plainText: String): String {
        encryptedPairData = getEncryptedDataPair(plainText)
        return encryptedPairData.second.toString(Charsets.UTF_8)

    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getKeyGenerator() {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGeneratorSpec = KeyGenParameterSpec.Builder(
            "myKey",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(false)
            .build()
        keyGenerator.init(keyGeneratorSpec)
        keyGenerator.generateKey()
    }

    private fun getKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secreteKeyEntry: KeyStore.SecretKeyEntry =
            keyStore.getEntry("myKey", null) as KeyStore.SecretKeyEntry
        return secreteKeyEntry.secretKey
    }

    private fun getEncryptedDataPair(data: String): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getKey())

        val _iv: ByteArray = cipher.iv
        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return Pair(_iv, encryptedData)
    }

    private fun decryptData(iv: ByteArray, encData: ByteArray): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val keySpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, getKey(), keySpec)
        return cipher.doFinal(encData).toString(Charsets.UTF_8)

    }
}