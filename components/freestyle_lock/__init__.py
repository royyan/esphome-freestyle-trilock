# Minimal working registration - no extras, just proves loading
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import lock
from esphome.const import CONF_ID, CONF_NAME

DEPENDENCIES = ["esp32_ble_client"]

ns = cg.esphome_ns.namespace("freestyle_lock")
FreestyleLock = ns.class_("FreestyleLock", lock.Lock, cg.Component)

CONFIG_SCHEMA = lock.LOCK_SCHEMA.extend({
    cv.GenerateID(): cv.declare_id(FreestyleLock),
    cv.Required(CONF_NAME): cv.string,
}).extend(cv.COMPONENT_SCHEMA)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await lock.register_lock(var, config)
