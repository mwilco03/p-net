# RTU Team: Connection Support Instructions

**From**: p-net analysis (pcap-verified, code-traced)
**Date**: 2026-01-31
**Scope**: Water-treat repo (`mwilco03/Water-treat`)

---

## Current State

The RTU PROFINET implementation is structurally sound. The p-net library
handles connection acceptance, block parsing, and validation correctly.
The database-driven slot system works as designed. The primary connection
failures originate from the controller's wire encoding (documented separately).

This document covers:
1. Items the RTU team must verify/maintain for connection success
2. A new `/slots` HTTP endpoint (fallback mechanism, lowest priority)
3. GSDML consistency checks
4. Operational concerns

---

## Section 1: Verify Existing Implementation

### 1.1 DAP Submodule Idents Must Match GSDML

**File**: `src/profinet/profinet_manager.c`
**Lines**: 885-919

Current code:
```c
885  pnet_plug_module(g_pn.pnet, 0, 0, GSDML_MOD_DAP);
894  pnet_plug_submodule(g_pn.pnet, 0, 0, 1,
895                       GSDML_MOD_DAP, GSDML_SUBMOD_DAP,
896                       PNET_DIR_NO_IO, 0, 0);
906  pnet_plug_submodule(g_pn.pnet, 0, 0, 0x8000,
907                       GSDML_MOD_DAP, GSDML_SUBMOD_DAP_INTERFACE,
908                       PNET_DIR_NO_IO, 0, 0);
917  pnet_plug_submodule(g_pn.pnet, 0, 0, 0x8001,
918                       GSDML_MOD_DAP, GSDML_SUBMOD_DAP_PORT,
919                       PNET_DIR_NO_IO, 0, 0);
```

**Verify these constants match the GSDML**:

| Constant | Expected Value | GSDML Source |
|----------|---------------|--------------|
| `GSDML_MOD_DAP` | 0x00000001 | Line 52: DeviceAccessPointItem |
| `GSDML_SUBMOD_DAP` | 0x00000001 | Line 95: VirtualSubmoduleItem "VSM_DAP" |
| `GSDML_SUBMOD_DAP_INTERFACE` | 0x00000100 | Line 116: InterfaceSubmoduleItem |
| `GSDML_SUBMOD_DAP_PORT` | 0x00000200 | Line 130: PortSubmoduleItem |

**Subslot numbers**:
- DAP identity: subslot 1 (0x0001) at line 894
- Interface: subslot 0x8000 at line 906
- Port: subslot 0x8001 at line 917

These are standard PROFINET subslot assignments. Confirm the defines match.

**GSDML note**: Line 105 of the GSDML has a VirtualSubmoduleItem "VSM_Port1"
with `SubmoduleIdentNumber="0x00008000"`. This is in the VirtualSubmoduleList,
separate from the SystemDefinedSubmoduleList entries (0x00000100 and 0x00000200).
The code correctly uses the SystemDefined values. The 0x00008000 virtual
submodule may be vestigial — verify it's intentional or remove it from the GSDML
to avoid controller confusion.

---

### 1.2 Module Plugging from Database

**File**: `src/profinet/profinet_manager.c`
**Lines**: 930-953

```c
930  for (int i = 0; i < g_pn.slot_count; i++) {
931      profinet_slot_t *slot = &g_pn.slots[i];
933      int ret = pnet_plug_module(g_pn.pnet, 0, slot->slot, slot->module_ident);
939      pnet_submodule_dir_t direction = is_actuator_module(slot->module_ident)
940                                           ? PNET_DIR_OUTPUT
941                                           : PNET_DIR_INPUT;
943      ret = pnet_plug_submodule(g_pn.pnet, 0, slot->slot, slot->subslot,
944                                slot->module_ident, slot->submodule_ident,
945                                direction,
946                                slot->input_size, slot->output_size);
```

**Status**: This is correct. Modules are loaded from the `modules` SQLite table
via `db_module_list()` (`db_modules.c:176-227`), ordered by slot number.

**Empty database behavior**: If no modules are in the database, only DAP is
plugged. The controller will see a ModuleDiffBlock with MODULE_STATE_NO_MODULE
for any application slots it requests. This is correct PROFINET behavior.

**Action required**: Ensure the database is populated before PROFINET init.
The controller team needs at least one successful connection to validate
Phase 1 (DAP-only), which requires no database entries.

---

### 1.3 Station Name: Do Not Accept DCP Set-Name

**File**: `src/profinet/profinet_manager.c`
**Lines**: 185-243

The NV storage cleanup at lines 185-243 (`clear_pnet_nv_station()`) deletes
all `pf_*` files before `pnet_init()` to enforce the configured station name.
This prevents a controller's DCP Set-Name from overwriting the RTU's identity.

**Status**: Correct. The RTU generates its own name (`rtu-XXXX` from MAC) and
enforces it on every boot. No changes needed.

**Design agreement**: The controller team has been instructed to NOT use
DCP Set-Name. The RTU's station name is discovered via DCP Identify Response
and used as-is.

---

### 1.4 IP Address: RTU Owns Its IP

**File**: `src/profinet/profinet_manager.c`
**Lines**: 608-660

The RTU reads its IP from the system interface via `getifaddrs()`. Whether the
IP comes from DHCP or static configuration is a system-level concern, not a
PROFINET concern.

```c
612      if (getifaddrs(&ifaddr) != 0) { ... }
619      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
621          if (strcmp(ifa->ifa_name, iface) != 0) continue;
622          if (ifa->ifa_addr->sa_family != AF_INET) continue;
627          in_addr_to_pnet_ip(addr->sin_addr, &cfg->if_cfg.ip_cfg.ip_addr);
```

**Status**: Correct. The RTU reports its current IP. The controller discovers
it via DCP and connects to it.

**Design agreement**: The controller team has been instructed to NOT use
DCP Set to assign IP addresses.

---

### 1.5 Rapid Reconnect Stability

The pcap analysis showed the RTU stops responding after approximately 9
connection attempts (session exhaustion at frame 58). This is because p-net
has a limited number of AR (Application Relationship) slots, controlled by
`PNET_MAX_AR` in the p-net build configuration.

**File**: `p-net/pnet_options.h.in` (in the p-net library, not Water-treat)

When a failed connect request consumes an AR slot but doesn't cleanly release
it, subsequent requests find no available slots and are silently dropped.

**Mitigation**: p-net cleans up stale sessions on a timer, but rapid-fire
requests (as in the brute force pcap) can exhaust slots faster than cleanup.

**Action**: No RTU code change needed. The controller team has been instructed
to use a single correct wire format rather than rapid strategy cycling. If
session exhaustion is still observed after the controller fixes, consider
increasing `PNET_MAX_AR` in the p-net build or adding explicit session timeout
handling.

---

## Section 2: New `/slots` HTTP Endpoint (Fallback Only)

### Context

This is a NON-STANDARD extension. Standard PROFINET uses GSDML files and
ModuleDiffBlock/Record Read for module discovery. This HTTP endpoint is a
fallback for when the controller cannot obtain the GSDML file and standard
discovery mechanisms have failed.

The controller team's fallback chain:
1. Parse GSDML file (standard)
2. Use cached config from previous connection
3. **GET /slots from RTU HTTP** (this endpoint)
4. DAP-only connect + Record Read 0xF844

### Implementation

**File to modify**: `src/health/health_check.c`
**Location**: After line 688 (the `/config` endpoint handler)

Add a new endpoint that reads the modules table and returns the current
slot configuration as JSON.

### Endpoint specification

```
GET /slots
Content-Type: application/json
```

**Response when modules are loaded** (HTTP 200):
```json
{
  "slot_count": 3,
  "slots": [
    {
      "slot": 1,
      "subslot": 1,
      "module_ident": 16,
      "submodule_ident": 17,
      "module_type": "sensor",
      "name": "pH Sensor",
      "direction": "input",
      "input_size": 5,
      "output_size": 0
    },
    {
      "slot": 2,
      "subslot": 1,
      "module_ident": 256,
      "submodule_ident": 257,
      "module_type": "actuator",
      "name": "Main Pump",
      "direction": "output",
      "input_size": 0,
      "output_size": 4
    },
    {
      "slot": 5,
      "subslot": 1,
      "module_ident": 64,
      "submodule_ident": 65,
      "module_type": "sensor",
      "name": "Temperature",
      "direction": "input",
      "input_size": 5,
      "output_size": 0
    }
  ]
}
```

**Response when database is empty** (HTTP 200, no application modules):
```json
{
  "slot_count": 0,
  "slots": []
}
```

**Response when PROFINET not initialized** (HTTP 503):
```json
{
  "error": "PROFINET subsystem not initialized",
  "status": "unavailable"
}
```

### Implementation approach

The data source is the same `db_module_list()` function already used by
`profinet_manager.c` to plug modules. The `/slots` handler reads from the
database, not from the p-net runtime state, so it's available even before
`pnet_init()` completes.

```c
// In handle_http_request(), after the /config handler:

} else if (strcmp(path, "/slots") == 0) {
    /* Slot configuration endpoint (fallback for controller discovery) */
    slots_to_json(response_body, sizeof(response_body));
    content_type = "application/json";
}
```

The `slots_to_json()` function calls `db_module_list()` and formats each
module as a JSON object with the fields above. Use `is_actuator_module()`
(line 157-160) for direction determination.

### DAP is NOT included

The `/slots` response lists only application modules (slots 1-246).
DAP (slot 0) is always present and has a fixed configuration that the
controller already knows from the GSDML. Including it would be redundant.

---

## Section 3: GSDML Consistency

### File: `gsd/GSDML-V2.4-WaterTreat-RTU-20241222.xml`

### Items to verify

1. **PhysicalSlots** (line 54): `"0..246"` — 247 total slots.
   This matches the Modbus parity requirement (247 registers).

2. **MinDeviceInterval** (line 55): `"32"` — 32ms minimum.
   The controller's TIMING_CONSERVATIVE profile uses 256ms, which is
   a multiple of 32ms. Verified compatible.

3. **DAP Module Ident**: Must match `GSDML_MOD_DAP` constant.
   Standard p-net uses 0x00000001 for DAP. Verify this matches.

4. **VirtualSubmoduleItem "VSM_Port1"** (line 105):
   `SubmoduleIdentNumber="0x00008000"`. This value (0x00008000) is
   the standard PROFINET subslot number for the interface, NOT a
   submodule ident. This may be a GSDML authoring error:
   - The actual interface submodule ident is 0x00000100 (line 116)
   - The actual port submodule ident is 0x00000200 (line 130)
   - 0x00008000 as a submodule ident in VirtualSubmoduleList is
     potentially confusing to GSDML parsers

   **Recommendation**: Review whether line 105 should use 0x00000200
   (matching the PortSubmoduleItem) or be removed if it's redundant
   with the SystemDefinedSubmoduleList.

5. **Module UsableModules** definitions: Verify each sensor/actuator
   module type listed in the GSDML has a corresponding entry in the
   database schema and in `profinet_manager.c`'s `is_actuator_module()`.

---

## Section 4: Operational Notes

### Database population

The modules database drives everything. If empty, only DAP is plugged.
This is valid for Phase 1 testing (DAP-only connect).

For full operation, modules must be inserted before PROFINET init:

```sql
INSERT INTO modules (slot, subslot, name, module_type, module_ident,
                     submodule_ident, status)
VALUES (1, 1, 'pH Sensor', 'sensor', 16, 17, 'active');
```

Module idents are decimal in SQLite:
- 16 = 0x00000010 (pH)
- 17 = 0x00000011 (pH submodule)
- 256 = 0x00000100 (Pump)
- 257 = 0x00000101 (Pump submodule)

### Health check port

The HTTP server port is configurable via `[health] http_port` in
`/etc/water-treat/water-treat.conf`. Default varies by deployment.
The controller team uses port 9081 for RTU probing
(`web/api/app/api/v1/discover.py` probe-ip endpoint).

Ensure the RTU's health check port matches what the controller expects.

### p-net version

The RTU uses p-net v0.2.0. The analysis in this document was performed
against the p-net source in `mwilco03/p-net`, which appears consistent
with v0.2.0 behavior. Core RPC/NDR/block parsing logic is stable across
minor versions.

### Sensor data format

Sensors write 5 bytes per submodule (Float32 BE + quality byte).
Actuators read 4 bytes per submodule (command + duty + reserved).

The cyclic data update happens in `profinet_manager.c` via:
```c
pnet_input_set_data_and_iops()   // Sensor → Controller
pnet_output_get_data_and_iops()  // Controller → Actuator
```

These are called from the periodic handler. Ensure the data sizes passed
to `pnet_plug_submodule()` (input_size / output_size) match exactly what
the cyclic handler writes/reads.

---

## Verification Checklist

### Before first connection attempt

- [ ] DAP submodule idents match GSDML (0x00000001, 0x00000100, 0x00000200)
- [ ] Station name is set and NV storage is cleaned on boot
- [ ] Network interface has IPv4 address (DHCP or static)
- [ ] Health check HTTP server is running and reachable
- [ ] `CAP_NET_RAW` capability is available for p-net
- [ ] p-net NV directory exists and is writable

### For Phase 1 (DAP-only connect)

- [ ] Database can be empty (only DAP plugged)
- [ ] RTU responds to DCP Identify with correct station name and vendor/device ID
- [ ] RTU accepts Connect Request and returns Connect Response (not just error)

### For Phase 2+ (full connect)

- [ ] Database populated with correct module idents
- [ ] All modules in database match GSDML module definitions
- [ ] `is_actuator_module()` correctly classifies all module idents
- [ ] Input/output sizes match GSDML data lengths (5 bytes sensor, 4 bytes actuator)

### For HTTP fallback

- [ ] `/slots` endpoint returns correct JSON
- [ ] `/slots` returns HTTP 200 with empty array when no modules configured
- [ ] `/slots` returns HTTP 503 when subsystem unavailable
- [ ] Port matches controller's expected RTU health port (9081)
