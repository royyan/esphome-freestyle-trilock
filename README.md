# ESPHome Freestyle Trilock Custom Component

**Directory structure:**
- `esphome-freestyle-trilock.yaml`: Main config file; set your MAC & AES key here.
- `custom_components/freestyle_trilock/`: All BLE/protocol files including:
    - `freestyle_trilock_component.h` (main custom component)
    - `CRC.h` / `CRC.cpp` (helper)
    - `encoder.h` / `encoder.cpp` (from protocol repo)
    - `cmd.pb.h` / `cmd.pb.c` (from protocol repo)
    - `pb.h` / `pb_encode.h` / `pb_encode.c` / `pb_decode.h` / `pb_decode.c` (from NanoPB)
    - `__init__.py` (empty file, required)
- Build using ESPHome CLI or dashboard.

No code changes required to use different locks: Just edit the YAML for MAC/AES key.