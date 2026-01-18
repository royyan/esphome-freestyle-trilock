# components/freestyle_lock/__init__.py

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import lock
from esphome.const import CONF_ID, CONF_NAME

DEPENDENCIES = ["esp32_ble_client"]

freestyle_lock_ns = cg.esphome_ns.namespace("freestyle_lock")
FreestyleLock = freestyle_lock_ns.class_("FreestyleLock", lock.Lock, cg.Component)

CONF_BLE_MAC = "ble_mac"
CONF_AES_KEY = "aes_key"

CONFIG_SCHEMA = lock.LOCK_SCHEMA.extend({
    cv.GenerateID(): cv.declare_id(FreestyleLock),
    cv.Required(CONF_NAME): cv.string,
    cv.Required(CONF_BLE_MAC): cv.string_strict,
    cv.Required(CONF_AES_KEY): cv.string_strict,
}).extend(cv.COMPONENT_SCHEMA)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await lock.register_lock(var, config)
    cg.add(var.set_ble_mac(config[CONF_BLE_MAC]))
    cg.add(var.set_aes_key(config[CONF_AES_KEY]))
