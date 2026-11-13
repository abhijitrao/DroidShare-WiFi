package com.droidshare.wifi

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

data class TransferHistoryEntry(
    val id: String,
    val direction: String,
    val name: String,
    val status: String,
    val bytes: Long,
    val totalBytes: Long,
    val updatedAt: String
)

class TransferHistoryStore(context: Context) {
    private val preferences = context.getSharedPreferences("droidshare_transfer_history_v1", Context.MODE_PRIVATE)

    @Synchronized
    fun all(): List<TransferHistoryEntry> {
        val array = runCatching { JSONArray(preferences.getString("entries", "[]")) }.getOrElse { JSONArray() }
        return (0 until array.length()).mapNotNull { index ->
            runCatching {
                val item = array.getJSONObject(index)
                TransferHistoryEntry(
                    id = item.getString("id"),
                    direction = item.getString("direction"),
                    name = item.getString("name"),
                    status = item.getString("status"),
                    bytes = item.optLong("bytes"),
                    totalBytes = item.optLong("totalBytes"),
                    updatedAt = item.getString("updatedAt")
                )
            }.getOrNull()
        }
    }

    @Synchronized
    fun record(id: String, direction: String, name: String, status: String, bytes: Long, totalBytes: Long) {
        val current = all().filterNot { it.id == id }.toMutableList()
        current.add(
            0,
            TransferHistoryEntry(id, direction, name.take(240), status, bytes.coerceAtLeast(0),
                totalBytes.coerceAtLeast(0), Instant.now().toString())
        )
        val array = JSONArray()
        current.take(100).forEach { entry ->
            array.put(JSONObject()
                .put("id", entry.id)
                .put("direction", entry.direction)
                .put("name", entry.name)
                .put("status", entry.status)
                .put("bytes", entry.bytes)
                .put("totalBytes", entry.totalBytes)
                .put("updatedAt", entry.updatedAt))
        }
        preferences.edit().putString("entries", array.toString()).apply()
    }

    @Synchronized
    fun recoverInterrupted() {
        all().filter { it.status == "Running" || it.status == "Paused" }.forEach { entry ->
            record(entry.id, entry.direction, entry.name, "Interrupted", entry.bytes, entry.totalBytes)
        }
    }

    @Synchronized
    fun updateStatus(id: String, status: String, bytes: Long, totalBytes: Long) {
        val entry = all().firstOrNull { it.id == id } ?: return
        record(id, entry.direction, entry.name, status, bytes, totalBytes)
    }

    @Synchronized
    fun clear() {
        preferences.edit().remove("entries").apply()
    }

    companion object {
        fun newId(): String = UUID.randomUUID().toString()
    }
}
