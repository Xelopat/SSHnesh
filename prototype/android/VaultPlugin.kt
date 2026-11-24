package ru.xelopat.sshnesh.preview

import android.app.Activity
import android.app.KeyguardManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg class VaultArgs { lateinit var owner: String; var value: String = "" }

@TauriPlugin
class VaultPlugin(private val screen: Activity) : Plugin(screen) {
    private val prefs get() = screen.getSharedPreferences("vault-device-keys", 0)
    private fun run(request: Invoke, action: String) {
        try {
            val args = request.parseArgs(VaultArgs::class.java)
            val login = args.owner.matches(Regex("oauth-[0-9a-f]{16}"))
            require(login || args.owner.matches(Regex("[0-9a-f]{16}")))
            val alias = "SSHnesh.Vault." + args.owner
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val result = JSObject()
            if (action == "forget") {
                if (ks.containsAlias(alias)) ks.deleteEntry(alias)
                check(prefs.edit().remove(alias).commit())
            } else {
                val guard = screen.getSystemService(KeyguardManager::class.java)
                require(login || (Build.VERSION.SDK_INT >= 28 && guard.isDeviceSecure && !guard.isDeviceLocked))
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                if (action == "store") {
                    val key = (ks.getKey(alias,null) as? SecretKey) ?: KeyGenerator.getInstance("AES","AndroidKeyStore").run {
                        init(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .apply { if (!login && Build.VERSION.SDK_INT >= 28) setUnlockedDeviceRequired(true) }.build())
                        generateKey()
                    }
                    cipher.init(Cipher.ENCRYPT_MODE,key)
                    val data = cipher.iv + cipher.doFinal(args.value.toByteArray(Charsets.UTF_8))
                    check(prefs.edit().putString(alias,Base64.encodeToString(data,Base64.NO_WRAP)).commit())
                } else {
                    val data = Base64.decode(requireNotNull(prefs.getString(alias,null)),Base64.NO_WRAP)
                    cipher.init(Cipher.DECRYPT_MODE,ks.getKey(alias,null),GCMParameterSpec(128,data,0,12))
                    val plain = cipher.doFinal(data,12,data.size-12)
                    try { result.put("value",String(plain,Charsets.UTF_8)) } finally { plain.fill(0) }
                }
            }
            request.resolve(result)
        } catch (e: Exception) { request.reject("Системный ключ недоступен. Разблокируйте устройство или введите мастер-пароль.") }
    }
    @Command fun store(invoke: Invoke) = run(invoke,"store")
    @Command fun read(invoke: Invoke) = run(invoke,"read")
    @Command fun forget(invoke: Invoke) = run(invoke,"forget")
}
