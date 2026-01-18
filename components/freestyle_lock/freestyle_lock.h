#pragma once

#include "esphome.h"
#include "esphome/components/lock/lock.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/components/esp32_ble_client/esp32_ble_client.h"
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <vector>

using namespace esphome;
using namespace esphome::lock;
using namespace esphome::esp32_ble_tracker;
using namespace esphome::esp32_ble_client;

#define SERVICE_UUID "00000001-4757-4100-6c78-67726f757000"
#define CMD_CHANNEL_UUID "00000301-4757-4100-6c78-67726f757000"
#define TIMEOUT_MS 10000

namespace freestyle_lock {

class FreestyleLock : public lock::Lock, public Component, public BLEClientNode {
 public:
  void setup() override {
    size_t outlen;
    int ret = mbedtls_base64_decode(aes_key_, 32, &outlen,
                                    (const unsigned char*)aes_key_str_.c_str(), aes_key_str_.length());
    if (ret != 0 || outlen != 32) {
      ESP_LOGE("freestyle_lock", "Invalid AES key (must be 32-byte base64)");
    }
  }

  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override {
    switch (event) {
      case ESP_GATTC_NOTIFY_EVT:
        if (param->notify.handle == char_handle_) {
          notify_callback_(param->notify.value, param->notify.value_len);
        }
        break;

      case ESP_GATTC_REG_FOR_NOTIFY_EVT:
        if (param->reg_for_notify.status == ESP_GATT_OK) {
          send_initial_();
        }
        break;

      default:
        break;
    }
  }

  void lock() override { control(2); }      // Lock
  void unlock() override { control(1); }    // Unlock
  void open() override { control(3); }      // Deadlock

  void set_ble_mac(const std::string &mac) { ble_mac_ = mac; }
  void set_aes_key(const std::string &key) { aes_key_str_ = key; }

 protected:
  std::string ble_mac_;
  std::string aes_key_str_;
  uint8_t aes_key_[32]{};

  uint8_t lock_nonce_[12]{};
  uint16_t msg_id_{};
  uint8_t encoded_msg_[512]{};
  size_t encoded_len_{};
  uint8_t sender_nonce_[12]{};
  int current_step_{-1};
  bool done_{false};
  uint32_t start_time_{};
  uint8_t desired_state_{};

  esp_ble_gattc_char_handle_t char_handle_{};

  void control(uint8_t state) {
    desired_state_ = state;
    current_step_ = 0;
    done_ = false;
    start_time_ = millis();

    publish_state(state == 1 ? LOCK_STATE_UNLOCKING : LOCK_STATE_LOCKING);

    set_address(BLEAddress(ble_mac_.c_str()));
    parent()->connect();
  }

  void send_initial_() {
    uint8_t init = 0x02;
    char_handle_->write_value(&init, 1);
    ESP_LOGD("freestyle_lock", "Sent initial 0x02");
  }

  void notify_callback_(const uint8_t* data, size_t len) {
    ESP_LOGD("freestyle_lock", "Notify %zu bytes", len);

    switch (current_step_) {
      case 0:
        if (len >= 20 && data[0] == 0x02 && data[1] == 0x00) {
          memcpy(lock_nonce_, data + 6, 12);
          msg_id_ = data[18] | (data[19] << 8);

          uint32_t token = esp_random();
          std::vector<uint8_t> pb;
          encode_protobuf_(desired_state_, token, pb);

          encoded_len_ = encode_message_(aes_key_, pb.data(), pb.size(), encoded_msg_, lock_nonce_, msg_id_ + 1);

          uint16_t nid = msg_id_ + 1;
          uint8_t hdr[5] = {0x20, (uint8_t)nid, (uint8_t)(nid >> 8), (uint8_t)encoded_len_, 0};
          char_handle_->write_value(hdr, 5);
          current_step_ = 1;
        }
        break;

      case 1:
        if (data[0] == 0x02 && data[1] == 0x03) {
          char_handle_->write_value(encoded_msg_, encoded_len_);

          uint32_t crc = calc_crc32_(encoded_msg_ + 2, encoded_len_ - 2);
          uint16_t nid = msg_id_ + 1;
          uint8_t end[9] = {0x21, (uint8_t)nid, (uint8_t)(nid >> 8), (uint8_t)encoded_len_, 0,
                            (uint8_t)crc, (uint8_t)(crc >> 8), (uint8_t)(crc >> 16), (uint8_t)(crc >> 24)};
          char_handle_->write_value(end, 9);
          current_step_ = 2;
        }
        break;

      case 2:
        if (data[0] == 0x02 && data[1] == 0x04) {
          uint8_t val = 0x01;
          char_handle_->write_value(&val, 1);
          current_step_ = 3;
        }
        break;

      case 3:
        if (len >= 13 && data[0] == 0x01 && data[1] == 0x00) {
          esp_fill_random(sender_nonce_, 12);
          uint8_t hdr[5] = {0x10, data[11], data[12], 0, 0};
          uint8_t req[17];
          memcpy(req, hdr, 5);
          memcpy(req + 5, sender_nonce_, 12);
          char_handle_->write_value(req, 17);
          current_step_ = 4;
        }
        break;

      case 4:
        if (len >= 23 && data[0] == 0x30) {
          uint16_t rid = data[1] | (data[2] << 8);
          uint16_t rlen = data[9] | (data[10] << 8);
          uint8_t rnonce[12];
          memcpy(rnonce, data + 11, 12);
          uint8_t dec[256];
          decode_message_(aes_key_, data + 23, len - 23, dec, sender_nonce_, rnonce, rid);
          uint8_t reported = parse_reported_(dec, rlen);
          ESP_LOGI("freestyle_lock", "Success - reported state: %d", reported);
          current_step_ = 5;
        }
        break;

      case 5:
        if (data[0] == 0x01 && data[1] == 0x02 && len >= 4) {
          uint8_t ack[3] = {0x12, data[2], data[3]};
          char_handle_->write_value(ack, 3);
          current_step_ = 6;
        }
        break;

      case 6:
        if (data[0] == 0x01 && data[1] == 0x06) {
          done_ = true;
          ESP_LOGI("freestyle_lock", "Protocol complete");
          publish_state(desired_state_ == 1 ? LOCK_STATE_UNLOCKED : LOCK_STATE_LOCKED);
          parent()->disconnect();
        }
        break;
    }

    if (done_ || (millis() - start_time_ > TIMEOUT_MS)) {
      if (!done_) ESP_LOGW("freestyle_lock", "Timeout");
      parent()->disconnect();
      publish_state(LOCK_STATE_NONE);
    }
  }

 private:
  uint8_t reflect_byte_(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
  }

  uint32_t reflect_dword_(uint32_t d) {
    d = (d & 0xFFFF0000) >> 16 | (d & 0x0000FFFF) << 16;
    d = (d & 0xFF00FF00) >> 8 | (d & 0x00FF00FF) << 8;
    d = (d & 0xF0F0F0F0) >> 4 | (d & 0x0F0F0F0F) << 4;
    d = (d & 0xCCCCCCCC) >> 2 | (d & 0x33333333) << 2;
    d = (d & 0xAAAAAAAA) >> 1 | (d & 0x55555555) << 1;
    return d;
  }

  uint32_t calc_crc32_(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
      uint32_t c = reflect_byte_(data[i]);
      crc ^= (c << 24);
      for (int j = 0; j < 8; ++j)
        crc = (crc & 0x80000000) ? ((crc << 1) ^ 0x04C11DB7) : (crc << 1);
    }
    return reflect_dword_(crc) ^ 0xFFFFFFFF;
  }

  size_t encode_protobuf_(uint8_t state, uint32_t token, std::vector<uint8_t>& out) {
    out = {0x0A, 0};
    size_t start = out.size();
    out.push_back(0x08);
    out.push_back(state);
    out.push_back(0x10);
    uint64_t v = token;
    do {
      out.push_back((v & 0x7F) | (v >= 0x80 ? 0x80 : 0));
      v >>= 7;
    } while (v);
    out[start - 1] = out.size() - start;
    return out.size();
  }

  int encode_message_(const uint8_t* key, const uint8_t* in, size_t ilen,
                      uint8_t* out, const uint8_t* iv1, uint16_t msgid) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    uint8_t iv[24];
    memcpy(iv, iv1, 12);
    esp_fill_random(iv + 12, 12);

    size_t pad = 16 - (ilen % 16);
    uint8_t padded[512];
    memcpy(padded, in, ilen);
    esp_fill_random(padded + ilen, pad);

    uint8_t hdr[6] = {0, 0, (uint8_t)(msgid >> 8), (uint8_t)msgid, (uint8_t)ilen, 0};

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, 24, hdr, 6);
    mbedtls_gcm_update(&ctx, ilen + pad, padded, out + 18);

    uint8_t tag[16];
    mbedtls_gcm_finish(&ctx, tag, 16);
    mbedtls_gcm_free(&ctx);

    memcpy(out, hdr, 6);
    memcpy(out + 6, iv + 12, 12);
    memcpy(out + 18 + ilen + pad, tag, 16);

    return 18 + ilen + pad + 16;
  }

  void decode_message_(const uint8_t* key, const uint8_t* in, size_t ilen, uint8_t* out,
                       const uint8_t* iv1, const uint8_t* iv2, uint16_t msgid) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    uint8_t iv[24];
    memcpy(iv, iv1, 12);
    memcpy(iv + 12, iv2, 12);

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, 24, nullptr, 0);
    mbedtls_gcm_update(&ctx, ilen, in, out);
    mbedtls_gcm_free(&ctx);
  }

  uint8_t parse_reported_(const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
      uint8_t tag = data[i++];
      int field = tag >> 3;
      int wire = tag & 7;
      if (field == 2 && wire == 0) {
        return data[i];
      }
      i++; // skip simple cases
    }
    return 0;
  }
};

}  // namespace freestyle_lock
