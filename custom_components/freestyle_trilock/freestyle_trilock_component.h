#pragma once
#include "esphome.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLEAddress.h>
#include <esp_random.h>
#include <mbedtls/gcm.h>
#include <string>
#include <vector>

// ----- DEPENDENCIES -----
#include "proto/cmd.pb.h"     // NanoPB protocol definitions
#include "encoder.h"          // from mcchas repo
#include "CRC.h"              // see above (must exist in same directory)
#include <pb_encode.h>
#include <pb_decode.h>
// ------------------------

// UUIDs for Gainsborough Freestyle Trilock
static const BLEUUID serviceUUID("00000001-4757-4100-6c78-67726f757000");
static const BLEUUID charUUID301("00000301-4757-4100-6c78-67726f757000");

static std::vector<uint8_t> hexstring_to_bytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (size_t i=0; i+1<hex.length(); i+=2)
        bytes.push_back((uint8_t)strtol(hex.substr(i,2).c_str(),nullptr,16));
    return bytes;
}

class FreestyleTrilockComponent : public esphome::Component {
public:
    FreestyleTrilockComponent(std::string mac_address, std::string aes_key) :
        mac_address_(mac_address),
        scan_time_(3),
        found_device_(false),
        connected_(false),
        desired_state_(cmd_State_STATE_UNKNOWN),
        ble_client_(nullptr),
        remote_char_(nullptr)
    {
        aes_key_bytes_ = hexstring_to_bytes(aes_key);
    }

    void setup() override {
        ESP_LOGI("TrilockBLE", "Starting BLE scan...");
        BLEDevice::init("");
        pBLEScan_ = BLEDevice::getScan();
        pBLEScan_->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks(this));
        pBLEScan_->setActiveScan(true);
    }

    void loop() override {
        if (!found_device_) {
            pBLEScan_->start(scan_time_, false);
            return;
        }
        if (!connected_) {
            connect_to_lock();
            return;
        }
        // Everything else is callback driven!
    }

    esphome::lock::Lock *get_lock() { return &lock_; }

    void control(const esphome::lock::LockCall &call) {
        if (!connected_ || !remote_char_) {
            ESP_LOGE("TrilockBLE", "Not connected");
            lock_.publish_state(false);
            return;
        }
        uint8_t desired;
        if (call.get_state().has_value() && *call.get_state())
            desired = cmd_State_LOCKED_PRIVACY;
        else
            desired = cmd_State_UNLOCKED;
        desired_state_ = desired;
        uint8_t cmd = 0x02;
        remote_char_->writeValue(&cmd, 1, true);
    }

private:
    BLEScan* pBLEScan_;
    int scan_time_;
    std::string mac_address_;
    std::vector<uint8_t> aes_key_bytes_;
    bool found_device_;
    bool connected_;
    uint8_t desired_state_;
    esphome::lock::Lock lock_;
    BLEClient* ble_client_;
    BLERemoteCharacteristic* remote_char_;
    unsigned char senderNonce[12] = {0};
    unsigned char encodedMessageData[128] = {0};
    uint8_t encodedMessageId[2] = {0,0};
    uint8_t encodedMessageDataLen = 0;

    class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
    public:
        MyAdvertisedDeviceCallbacks(FreestyleTrilockComponent *parent) : parent_(parent) {}
        void onResult(BLEAdvertisedDevice advertisedDevice) override {
            if (advertisedDevice.getAddress().toString() == parent_->mac_address_) {
                ESP_LOGI("TrilockBLE", "Found lock: %s", parent_->mac_address_.c_str());
                parent_->found_device_ = true;
            }
        }
    private:
        FreestyleTrilockComponent *parent_;
    };

    void connect_to_lock() {
        ble_client_ = BLEDevice::createClient();
        BLEAddress addr(mac_address_);
        if (ble_client_->connect(addr)) {
            ESP_LOGI("TrilockBLE", "Connected!");
            connected_ = true;
            auto *service = ble_client_->getService(serviceUUID);
            if (!service) { ESP_LOGE("TrilockBLE", "Lock service missing."); disconnect(); return; }
            remote_char_ = service->getCharacteristic(charUUID301);
            if (!remote_char_) { ESP_LOGE("TrilockBLE", "Lock characteristic missing."); disconnect(); return; }
            remote_char_->registerForNotify([this](BLERemoteCharacteristic *, uint8_t *data, size_t length, bool) {
                this->proto_callback(data, length);
            }, false);
        } else {
            ESP_LOGE("TrilockBLE", "BLE connect failed.");
        }
    }

    void disconnect() {
        connected_ = false;
        remote_char_ = nullptr;
        ble_client_->disconnect();
        lock_.publish_state(false);
    }

    // -------------- Main protocol handler for BLE notifications. --------------
    void proto_callback(uint8_t *data, size_t len) {
        if (len < 2) return;
        // Step 1: status query response, then build encrypted payload
        if (data[0] == 0x02 && data[1] == 0x00) {
            unsigned short msgId = (data[19]<<8 | data[18]);
            char nonce[12];
            memcpy(nonce, data+6, 12);

            unsigned char rand[4];
            esp_fill_random(rand, 4);
            unsigned long token = *((unsigned long *)rand);

            uint8_t buf[128];
            cmd_Request req = cmd_Request_init_zero;
            req.has_lockStateUpdate = true;
            req.lockStateUpdate.has_request = true;
            req.lockStateUpdate.request.has_desiredState = true;
            req.lockStateUpdate.request.has_desiredStateToken = true;
            req.lockStateUpdate.request.desiredState = (cmd_State)desired_state_;
            req.lockStateUpdate.request.desiredStateToken = token;
            pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
            if (!pb_encode(&stream, cmd_Request_fields, &req)) {
                ESP_LOGE("TrilockBLE", "nanopb encode failed!");
                return;
            }
            size_t message_length = stream.bytes_written;
            encodedMessageDataLen = encodeMessage(
                (char *)aes_key_bytes_.data(), buf, message_length,
                encodedMessageData, nonce, msgId+1);
            encodedMessageId[0] = (msgId+1)&0xFF;
            encodedMessageId[1] = ((msgId+1)>>8)&0xFF;
            // Step 2: tell lock we're sending payload
            uint8_t writeBack[] = {
                0x20,
                encodedMessageId[0],
                encodedMessageId[1],
                encodedMessageDataLen,
                0x00
            };
            remote_char_->writeValue(writeBack, sizeof(writeBack), true);
            return;
        }
        // Step 3: Ready to send actual message
        if (data[0] == 0x02 && data[1] == 0x03) {
            uint8_t header[] = { 0x30, encodedMessageId[0], encodedMessageId[1], 0x00, 0x00 };
            std::vector<uint8_t> sendMsg(header, header+sizeof(header));
            sendMsg.insert(sendMsg.end(), encodedMessageData, encodedMessageData+encodedMessageDataLen);
            remote_char_->writeValue(sendMsg.data(), sendMsg.size(), 1);

            uint32_t crc = calcCRC32(encodedMessageData + 2, encodedMessageDataLen - 2,
                                     0x04C11DB7, 0x00000000, 0xFFFFFFFF, true, true);
            uint8_t endMsg[] = {
                0x21,
                encodedMessageId[0],
                encodedMessageId[1],
                encodedMessageDataLen,
                0x00,
                (uint8_t)(crc),
                (uint8_t)(crc >> 8),
                (uint8_t)(crc >> 16),
                (uint8_t)(crc >> 24),
            };
            remote_char_->writeValue(endMsg, sizeof(endMsg), 1);
            return;
        }
        // Step 4: Confirmation message received
        if (data[0] == 0x30) {
            unsigned char rxNonce[12] = {};
            memcpy(rxNonce, data + 11, 12);
            unsigned short rxLen = ((uint16_t)(data[10] << 8) | (uint16_t)data[9]);
            unsigned short rxMsgId = ((uint16_t)(data[2] << 8) | (uint16_t)data[1]);
            uint8_t encLength = len - 23;
            unsigned char rxData[encLength] = {0};
            decodeMessage((char *)aes_key_bytes_.data(), data + 23, encLength, rxData, senderNonce, rxNonce, rxMsgId);

            cmd_Confirm message = cmd_Confirm_init_zero;
            pb_istream_t stream = pb_istream_from_buffer(rxData, rxLen);
            if (!pb_decode(&stream, cmd_Confirm_fields, &message)) {
                ESP_LOGE("TrilockBLE", "nanopb decode failed!");
                return;
            }
            if (message.has_lockStateConfirm && message.lockStateConfirm.has_confirm && message.lockStateConfirm.confirm.has_reportedState) {
                lock_.publish_state(message.lockStateConfirm.confirm.reportedState == cmd_State_LOCKED_PRIVACY);
            }
            return;
        }
    }
};

// ESPHome custom_component construction API
extern "C" FreestyleTrilockComponent *FreestyleTrilockComponent_constructor(std::string mac_address, std::string aes_key) {
    auto *comp = new FreestyleTrilockComponent(mac_address, aes_key);
    comp->get_lock()->add_on_lock_callback([comp](auto call) { comp->control(call); });
    return comp;
}